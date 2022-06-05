'use strict';

const aws = require('aws-sdk');
const axios = require('axios').default;
const crypto = require('crypto');
const msal = require('@azure/msal-node');

const xmlc = require('xml-crypto');
const xml2js = require('xml2js');
const Parser = require('@xmldom/xmldom').DOMParser;

const sm = new aws.SecretsManager({ region: "us-west-2" });
const ddb = new aws.DynamoDB.DocumentClient({ region: "us-west-2" });
const kms = new aws.KMS({ region: "us-west-2" });

async function getToken(id, tenant, secret) {
	const cca = new msal.ConfidentialClientApplication({
		auth: {
			clientId: id,
			authority: `https://login.microsoftonline.com/${tenant}`,
			clientSecret: secret,
		}
	});

	return await cca.acquireTokenByClientCredential({
		scopes: ['https://graph.microsoft.com/.default']
	});
}

exports.main = async function (event, context, callback) {
	// console.log(JSON.stringify(event))

	if (event.requestContext.httpMethod != "POST") {
		return callback({
			statusCode: 403,
			body: "You can't do that here."
		});
	}

	let body = event.body;
	if (event.isBase64Encoded) {
		body = new Buffer.from(body, 'base64').toString();
	}

	if (body.indexOf('SAMLResponse=') !== 0) {
		return callback(null, {
			statusCode: 400,
			headers: {},
			body: "Invalid request"
		});
	}

	const ip = event.headers['X-Forwarded-For'].split(', ')[0];

	const saml_token = decodeURIComponent(body.split('SAMLResponse=')[1]);
	const key = sha256(saml_token);

	const saml_response = Buffer.from(saml_token, 'base64').toString('ascii');

	// console.log(saml_response);

	const saml_object = await xml2js.parseStringPromise(saml_response);

	// console.log(JSON.stringify(saml_object));

	const tenant = saml_object["samlp:Response"]?.["Issuer"]?.[0]?.["_"].split('/')[3];

	// console.log(tenant);

	if (tenant != process.env.TENANT_ID) {
		return callback(null, {
			statusCode: 400,
			headers: {},
			body: "Invalid issuer"
		});
	}

	const metadata = await axios.get(`https://login.microsoftonline.com/${process.env.TENANT_ID}/federationmetadata/2007-06/federationmetadata.xml?appid=${process.env.APPLICATION_ID}`);
	const metadataXml = new Parser().parseFromString(metadata.data);

	// Verify the assertion against the published metadata
	const expectedIssuer = metadataXml.documentElement.getAttribute('entityID');

	validateSignedXml(metadataXml);


	const saml_acs_domain = saml_object["samlp:Response"]?.["$"]?.Destination?.split('/')?.[2];
	const saml_attributes = saml_object["samlp:Response"]?.Assertion?.[0]?.AttributeStatement?.[0]?.Attribute;
	const issued = new Date(saml_object["samlp:Response"]?.Assertion?.[0]?.["$"]?.IssueInstant).getTime();
	// console.log(`Issued delta: ${new Date() - issued}`);

	if (isNaN(issued) || new Date() - issued > 300000) {
		return callback(null, {
			statusCode: 400,
			headers: {},
			body: "Invalid assertion issuance instant"
		});
	}

	const expiry = new Date(issued + 300000);
	// console.log(`Expiry: ${expiry}`);

	const expires = expiry
		.getTime()
		.toString()
		.substr(0, 10);

	const [secret, publicKey] = await Promise.all([
		sm.getSecretValue({
			SecretId: process.env.SECRET_ID
		}).promise(),
		kms.getPublicKey({
			KeyId: process.env.KMS_KEY_ID
		}).promise()
	]);

	const authResponse = await getToken(process.env.APPLICATION_ID, process.env.TENANT_ID, secret.SecretString);

	axios.interceptors.response.use(function (response) {
		return response;
	}, function (error) {
		return Promise.resolve({ data: false });
	});

	const group_promises = saml_object["samlp:Response"].Assertion[0].AttributeStatement[0].Attribute
		.filter(e => e.$.Name == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role")
		.flatMap(e => e.AttributeValue)
		.map(e => axios.get(`https://graph.microsoft.com/v1.0/groups/${e}`, {
			headers: {
				Authorization: `Bearer ${authResponse.accessToken}`
			}
		}));

	const group_responses = await Promise.all(group_promises);
	const group_names = group_responses
		.filter(e => !!e.data)
		.map(e => e.data.displayName);

	const assertion = getAssertion(new Parser().parseFromString(saml_response), {
		issuer: `https://${process.env.CLOUDFRONT_DOMAIN}/`,
		destination: (process.env.USE_STYX_VIEW == "true") ? `https://${process.env.CLOUDFRONT_DOMAIN}/styx` : "https://signin.aws.amazon.com/saml",
		duration: 28800,
		group_names
	});

	const signedAssertion = await getSignedXml(assertion.toString(), process.env.KMS_KEY_ID);

	console.log(signedAssertion);

	const signedB64 = new Buffer.from(signedAssertion, 'ascii').toString('base64');

	await ddb.put({
		TableName: "acs_assertions",
		Item: { key, ip, saml_token: signedB64, expires }
	}).promise();

	if (process.env.USE_STYX_VIEW == "true") {
		return callback(null, {
			statusCode: 302,
			headers: {
				'Access-Control-Allow-Origin': `https://${saml_acs_domain}`,
				'Set-Cookie': `key=${key}; Domain=${saml_acs_domain}; path=/; SameSite=Strict; Secure; Expires=${expiry.toUTCString()}`,
				Location: `/#/saml`
			},
			body: "redirecting"
		});
	} else {
		return callback(null, {
			statusCode: 200,
			headers: {
				'Content-Type': 'text/html'
			},
			body: `<html><body bgcolor="#223035" onload="document.getElementsByTagName('form')[0].submit()"><div style="text-align: center;"><img src="assets/images/logo-icon.png"><br><img height="50" width="50" src="assets/images/loading.gif"></div><form method="POST" action="https://signin.aws.amazon.com/saml"><input name="SAMLResponse" type="hidden" value="${signedB64}"></form></body></html>`
		})
	}
}

function getUnsignedAssertion(options) {
	return new Promise((success, failure) => {
		saml.createUnsignedAssertion(options, success);
	});
}

function sha256(what) {
	return crypto.createHash('sha256').update(what).digest('hex');
}

function kmsKeyInfo() {
	this.getKeyInfo = function(key, prefix) {
		prefix = prefix || '';
        prefix = prefix ? prefix + ':' : prefix;
        return `<${prefix}X509Data><${prefix}X509Certificate>${process.env.KMS_PUBKEY}</${prefix}X509Certificate></${prefix}X509Data>`;
	};

	this.getKey = function(keyInfo) {
		console.log(keyInfo);

		return process.env.KMS_KEY_ID;
	};
}

function rawKeyInfo(key) {
	this.key = key;

	this.getKeyInfo = function(key, prefix) {
		return "<X509Data></X509Data>";
	};

	this.getKey = function(keyInfo) {
		return `-----BEGIN CERTIFICATE-----\n${this.key}\n-----END CERTIFICATE-----`;
	}
}

function kmsSigAlgorithm() {
	this.getSignature = async function(signedInfo, signingKey, cb) {
		console.log("\n");

		const sign = await kms.sign({
			KeyId: signingKey,
			Message: signedInfo,
			MessageType: "RAW",
			SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256"
		}).promise();

		const sig = new Buffer.from(sign.Signature).toString('base64');

		cb(null, sig);
	};

	this.getAlgorithmName = function() {
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
	}
}

function getAssertion(doc, options) {

	// Remove the existing signature
	const sigElement = doc.documentElement.getElementsByTagName('Signature')[0];
	sigElement.parentNode.removeChild(sigElement);

	// Set Destination
	doc.documentElement.setAttribute('Destination', options.destination);
	doc.documentElement.getElementsByTagName('SubjectConfirmationData')[0].setAttribute('Recipient', options.destination);

	// Set Issuer
	[...each(doc.documentElement.getElementsByTagName('Issuer'))].forEach(e => e.textContent = options.issuer);

	// Remove MS Roles
	const msRoleElement = [...each(doc.documentElement.getElementsByTagName('Attribute'))]
		.filter(e => e.getAttribute('Name') == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role")[0];

	// Add AWS Roles
	const attributeStatementElement = doc.documentElement.getElementsByTagName('AttributeStatement')[0];
	const awsRoleElement = doc.createElement('Attribute');
	awsRoleElement.setAttribute('Name', 'https://aws.amazon.com/SAML/Attributes/Role');

	options.group_names
		.filter(e => /AWS_(\d+)_([a-zA-Z]+)/.test(e))
		.map(e => {
			const [, account_id, role_name] = /AWS_(\d+)_([a-zA-Z]+)/g.exec(e);

			// console.log(/AWS_(\d+)_([a-zA-Z]+)/g.exec(e));

			const value = doc.createElement('AttributeValue');
			value.textContent = `arn:aws:iam::${account_id}:saml-provider/styx,arn:aws:iam::${account_id}:role/${role_name}`;

			awsRoleElement.appendChild(value);
		});

	attributeStatementElement.removeChild(msRoleElement);
	attributeStatementElement.appendChild(awsRoleElement);

	// Add AWS RoleSessionName
	const roleSessionNameAttribute = [...each(doc.documentElement.getElementsByTagName('Attribute'))]
		.filter(e => e.getAttribute('Name') == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")[0]
		.cloneNode(true);

	roleSessionNameAttribute.setAttribute('Name', 'https://aws.amazon.com/SAML/Attributes/RoleSessionName');

	attributeStatementElement.appendChild(roleSessionNameAttribute)

	// Add AWS RoleSessionDuration
	const roleSessionDurationValue = doc.createElement('AttributeValue');
	roleSessionDurationValue.textContent = options.duration;

	const roleSessionDurationAttribute = doc.createElement('Attribute');
	roleSessionDurationAttribute.setAttribute('Name', 'https://aws.amazon.com/SAML/Attributes/RoleSessionDuration')
	roleSessionDurationAttribute.appendChild(roleSessionDurationValue);

	attributeStatementElement.appendChild(roleSessionDurationAttribute);

	return doc;
}

function* each(nodelist) {
	for (let a = 0; a < nodelist.length; a++) {
		yield nodelist[a];
	}
}

function getSignedXml(xml, key) {
	const sig = new xmlc.SignedXml();
	sig.signatureAlgorithm = "http://kmsSigAlgorithm";
	sig.keyInfoProvider = new kmsKeyInfo();

	sig.addReference(
		"//*[local-name(.)='Assertion']",
		["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
		'http://www.w3.org/2001/04/xmlenc#sha256'
	);

	sig.signingKey = key;

	return new Promise((success, failure) => {
		sig.computeSignature(xml, {
			//location: { reference: "//*[local-name(.)='Issuer']", action: 'after' },
			location: { reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: 'after' },
			prefiX: ''
		}, (err) => {
			return success(sig.getSignedXml());
		});
	});
}

function validateSignedXml(xml) {
	const signature = xmlc.xpath(xml, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
	const certificate = xmlc.xpath(xml, "//*[local-name(.)='X509Certificate']/text()")[0].toString();

	const sig = new xmlc.SignedXml();
	sig.keyInfoProvider = new rawKeyInfo(certificate);
	//sig.signingKey = certificate.toString();
	sig.loadSignature(signature);
	const result = sig.checkSignature(xml.toString());

	if (result) {
		return true;
	} else {
		console.log(sig.validationErrors);
		return false;
	}

}

xmlc.SignedXml.SignatureAlgorithms["http://kmsSigAlgorithm"] = kmsSigAlgorithm;
