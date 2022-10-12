'use strict';

const aws = require('aws-sdk');
const crypto = require('crypto');
const xml2js = require('xml2js');

const ddb = new aws.DynamoDB.DocumentClient({ region: "us-west-2" });

exports.main = async (event, context, callback) => {
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

	const saml_response = Buffer.from(saml_token, 'base64');
	const saml_object = await xml2js.parseStringPromise(saml_response.toString());

	// console.log(JSON.stringify(saml_object));

	const saml_acs_domain = saml_object["samlp:Response"]?.["$"]?.Destination?.split('/')?.[2];
	const saml_attributes = saml_object["samlp:Response"]?.Assertion?.[0]?.AttributeStatement?.[0]?.Attribute;
	const issued = new Date(saml_object["samlp:Response"]?.Assertion?.[0]?.["$"]?.IssueInstant).getTime();
	console.log(`Issued delta: ${new Date() - issued}`);

	if (isNaN(issued) || new Date() - issued > 300000) {
		return callback(null, {
			statusCode: 400,
			headers: {},
			body: "Invalid assertion issuance instant"
		});
	}

	const expiry = new Date(issued + 300000);
	console.log(`Expiry: ${expiry}`);

	const expires = expiry
		.getTime()
		.toString()
		.substr(0, 10);

	await ddb.put({
		TableName: "acs_assertions",
		Item: { key, ip, saml_token, expires }
	}).promise();

	console.log(`key=${key}; SameSite=Strict; Secure; Expires=${expiry.toUTCString()}`);

	return callback(null, {
		statusCode: 302,
		headers: {
			'Access-Control-Allow-Origin': `https://${saml_acs_domain}`,
			'Set-Cookie': `key=${key}; Domain=${saml_acs_domain}; path=/; SameSite=Strict; Secure; Expires=${expiry.toUTCString()}`,
			Location: `/#/saml`
		},
		body: "redirecting"
	});
}

function sha256(what) {
	return crypto.createHash('sha256').update(what).digest('hex');
}