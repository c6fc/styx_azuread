#! /usr/bin/env node

'use strict';

const fs = require('fs');
const yargs = require("yargs");

const x509 = require('@peculiar/x509');
const { Crypto } = require('@peculiar/webcrypto');

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

const alg = {
	name: "RSASSA-PKCS1-v1_5",
	hash: "SHA-256",
	publicExponent: new Uint8Array([1, 0, 1]),
	modulusLength: 2048,
};

const createCertificate = async (subject, years, pubkey, output_file) => {
	const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);	

	const cert = await x509.X509CertificateGenerator.create({
		serialNumber: "01",
		subject: subject,
		issuer: subject,
		notBefore: new Date(),
		notAfter: new Date(Date.now() + (years * 365 * 24 * 3600 * 1000)),
		signingAlgorithm: alg,
		signingKey: keys.privateKey,
		publicKey: {
			publicKey: {
				rawData: fs.readFileSync(pubkey)
			}
		},
		extensions: [
			new x509.BasicConstraintsExtension(true, 2, true),
			new x509.ExtendedKeyUsageExtension(["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"], true),
			new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
			await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
		]
	});

	fs.writeFileSync(output_file, cert.toString("base64"));

	return true;
};

(async () => {

	yargs
		.usage("Syntax: $0 generate <cert_subj> <years> <pubkey_file> <output_file>")
		.command("generate <cert_subj> <years> <pubkey_file> <output_file>", "Create a certificate", (yargs) => yargs, async (argv) => {
			await createCertificate(argv.cert_subj, argv.years, argv.pubkey_file, argv.output_file);
		})
		.showHelpOnFail(false)
		.help("help")
		.argv;
})();
