'use strict';

const aws = require('aws-sdk');
const crypto = require('crypto');
const xml2js = require('xml2js');

const ddb = new aws.DynamoDB.DocumentClient({ region: "us-west-2" });

exports.main = async (event, context, callback) => {
	console.log(JSON.stringify(event))

	if (event.requestContext.httpMethod != "GET") {
		return callback({
			statusCode: 403,
			body: "You can't do that here."
		});
	}

	if (event.headers.Cookie.indexOf('key=') !== 0) {
		return callback(null, {
			statusCode: 400,
			headers: {},
			body: "Invalid request"
		});
	}

	const key = event.headers.Cookie.split("key=")[1].split(';')[0];
	const ip = event.headers['X-Forwarded-For'].split(', ')[0];

	console.log(key, ip);

	const ddb_record = await ddb.get({
		TableName: "acs_assertions",
		Key: { key, ip }
	}).promise();

	console.log(ddb_record);

	const saml_response = Buffer.from(ddb_record.Item.saml_token, 'base64').toString('ascii');

	console.log(saml_response);

	const saml_object = await xml2js.parseStringPromise(saml_response);

	console.log(JSON.stringify(saml_object));

	const saml_attributes = saml_object["samlp:Response"]?.Assertion?.[0]?.AttributeStatement?.[0]?.Attribute;
	const email = saml_attributes
		.filter(e => e["$"].Name == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")[0].AttributeValue[0];

	const expires = new Date(saml_object["samlp:Response"]?.Assertion?.[0]?.Conditions?.[0]?.["$"]?.NotOnOrAfter)
		.getTime();

	if (expires - new Date() < 0) {
		return callback(null, {
			statusCode: 400,
			headers: {},
			body: "Token expired"
		});
	}

	const issued = new Date(saml_object["samlp:Response"]?.Assertion?.[0]?.["$"]?.IssueInstant)
		.getTime();

	if (new Date() - issued > 300000) {
		return callback(null, {
			statusCode: 400,
			headers: {},
			body: "Token must be exchanged wtihin 5 minutes of issuance."
		});
	}

	const role_entitlements = saml_object["samlp:Response"].Assertion[0].AttributeStatement[0].Attribute
		.filter(e => e.$.Name == "https://aws.amazon.com/SAML/Attributes/Role")
		.flatMap(e => e.AttributeValue);

	console.log(JSON.stringify(role_entitlements, saml_attributes));

	return callback(null, {
		statusCode: "200",
		headers: {
			'Content-Type': "application/json"
		},
		body: JSON.stringify({ role_entitlements, email, issued })
	});

	/*const saml_response = Buffer.from(saml_token, 'base64');
	const saml_object = await xml2js.parseStringPromise(saml_response.toString());

	const saml_attributes = saml_object["samlp:Response"]?.Assertion?.[0]?.AttributeStatement?.[0]?.Attribute;

	const roles_entitlements = saml_object["samlp:Response"].Assertion[0].AttributeStatement[0].Attribute
		.filter(e => e.$.Name == "https://aws.amazon.com/SAML/Attributes/Role")
		.flatMap(e => e.AttributeValue);

	console.log(JSON.stringify(roles_entitlements));

	if (roles_entitlements.length < 1) {
		return callback({
			statusCode: "400",
			headers: {},
			body: "Invalid request"
		});
	}

	const roles_links = roles_entitlements.map(e => {
		const [idp, role] = e.split(',');

		return `<tr><td>${role.split(':')[5]}</td><td><a onClick="getCreds('${idp}', '${role}')">[Go]</a></td></tr>`;
	});

	const interpolated = template.toString()
		.replace('<<roles_links>>', roles_links)
		.replace('<<saml_assertion>>', saml_response);

	return callback(null, {
		statusCode: "200",
		headers: {
			"content-type": "text/html"
		},
		body: interpolated
	});*/
}

function sha256(what) {
	return crypto.createHash('sha256').update(what).digest('hex');
}