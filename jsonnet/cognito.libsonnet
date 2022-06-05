{
	saml_backed_identity_pool(name, provider_details, endpoint, custom_domain): {
		resource: {
			aws_cognito_user_pool: {
				[name]: {
					name: name,
					mfa_configuration: "OFF",
					password_policy: {
						minimum_length: 12,
						require_lowercase: true,
						require_uppercase: true,
						require_symbols: false,
						require_numbers: true
					},
					admin_create_user_config: {
						allow_admin_create_user_only: true
					},
					auto_verified_attributes: ["email"],
					username_attributes: ["email"]
				}
			},
			aws_cognito_user_pool_client: {
				[name]: {
					name: "%s_client" % name,
					user_pool_id: "${aws_cognito_user_pool.%s.id}" % name,
					generate_secret: false,
					allowed_oauth_flows_user_pool_client: "true",
					supported_identity_providers: ["${aws_cognito_identity_provider.%s.provider_name}" % name],
					allowed_oauth_scopes: ["email", "openid"],
					allowed_oauth_flows: ["code"],
					callback_urls: ["https://%s" % endpoint],
					logout_urls: ["https://%s" % endpoint]
				}
			},
			aws_cognito_identity_pool: {
				[name]: {
					identity_pool_name: name,
					allow_unauthenticated_identities: false,
					cognito_identity_providers: {
						client_id: "${aws_cognito_user_pool_client.%s.id}" % name,
						provider_name: "${aws_cognito_user_pool.%s.endpoint}" % name,
						server_side_token_check: false,
					}
				}
			},
			aws_cognito_identity_provider: {
				[name]: {
					user_pool_id: "${aws_cognito_user_pool.%s.id}" % name,
					provider_name: "SAML",
					provider_type: "SAML",

					provider_details: provider_details,

					attribute_mapping: {
						email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
					}
				}
			}
		} + (if !custom_domain then {
			random_string: {
				['%s_saml_domain' % name]: {
					length: 16,
					special: false,
					upper: false,
					min_numeric: 1,
					min_lower: 1
				}
			},
			aws_cognito_user_pool_domain: {
				[name]: {
					domain: "${random_string.%s_saml_domain.result}" % name,
					user_pool_id: "${aws_cognito_user_pool.%s.id}" % name
				}
			}
		} else {
			aws_cognito_user_pool_domain: {
				saml: {
					depends_on: ["aws_route53_record.www"],
					domain: custom_domain,
					certificate_arn: "${aws_acm_certificate.%s.arn}" % name,
					user_pool_id: "${aws_cognito_user_pool.%s.id}" % name
				}
			}
		})
	}
}