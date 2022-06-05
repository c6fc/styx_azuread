'use strict';

exports.main = async (event, context, callback) => {
	console.log(JSON.stringify(event));

	Object.assign(event.Records[0].cf.response.headers, {
		"access-control-allow-origin": [{
			key: "Access-Control-Allow-Origin",
			value: "*"
		}]
	});

	callback(null, event.Records[0].cf.response);

}