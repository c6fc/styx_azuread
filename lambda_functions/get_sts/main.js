'use strict';

const aws = require('aws-sdk');
const crypto = require('crypto');
const xml2js = require('xml2js');

const ddb = new aws.DynamoDB.DocumentClient({ region: "us-west-2" });
const sts = new aws.STS({ region: "us-west-2" });

exports.main = async (event, context, callback) => {
	console.log(JSON.stringify(event))

	if (event.requestContext.httpMethod != "GET") {
		return callback(null, {
			statusCode: 403,
			body: "You can't do that here."
		});
	}

	if (event.headers.Cookie.indexOf('key=') !== 0) {
		return callback(null, {
			statusCode: 401,
			headers: {},
			body: "Authorization required"
		});
	}

	if (!event.queryStringParameters.index) {
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

	const saml_response = Buffer.from(ddb_record.Item.saml_token, 'base64');
	const saml_object = await xml2js.parseStringPromise(saml_response.toString());

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

	const index = event.queryStringParameters.index;

	if (isNaN(index) || index < 0 || index > role_entitlements.length) {
		return callback({
			status: "400",
			headers: {},
			body: "Invalid request"
		});
	}

	const [ PrincipalArn, RoleArn ] = role_entitlements[index].split(',');

	console.log(PrincipalArn, RoleArn);
	
	try {
		const credentials = await sts.assumeRoleWithSAML({
			PrincipalArn,
			RoleArn,
			SAMLAssertion: ddb_record.Item.saml_token
		}).promise();

		return callback(null, {
			statusCode: "200",
			headers: {
				'Content-Type': "application/json"
			},
			body: JSON.stringify(credentials.Credentials)
		});
	} catch (e) {
		console.log(e);

		return callback(null, {
			statusCode: "200",
			headers: {
				'Content-Type': "application/json"
			},
			body: JSON.stringify({ success: false, msg: e })
		});
	}
}

function sha256(what) {
	return crypto.createHash('sha256').update(what).digest('hex');
}