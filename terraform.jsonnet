local aws = import 'aws-sdk';
local sonnetry = import 'sonnetry';

local settings = import 'settings.jsonnet';

local provider = import 'jsonnet/provider.libsonnet';

local api_gateway_map = import 'jsonnet/api_gateway_map.libsonnet';
local cognito = import 'jsonnet/cognito.libsonnet';
local iam = import 'jsonnet/iam.libsonnet';
local lambda = import 'jsonnet/lambda.libsonnet';

{
	'backend.tf.json': sonnetry.bootstrap('c6fc_styx-azuread'),
	'api_gateway.tf.json': api_gateway_map.rest_api('styx_azuread', {
  		parameters: {
  			endpoint_configuration: {
  				types: ["EDGE"]
  			}
  		},
  		deployment: {
  			stage_name: "v1"
  		},
  		root: {
  			children: [{
  				pathPart: "acs",
  				methods: {
  					POST: {
						lambdaIntegration: "acs_parser",
						parameters: {
							authorization: "NONE"
						}
					},
  					OPTIONS: {
  						optionsIntegration: true,
  						parameters: {
	  						authorization: "NONE"
						}
  					}
  				}
  			}, {
  				pathPart: "console",
				methods: {
  					GET: {
						lambdaIntegration: "get_console",
						parameters: {
							authorization: "NONE",
						}
					},
  					OPTIONS: {
  						optionsIntegration: true,
  						parameters: {
	  						authorization: "NONE"
						}
  					}
  				}
  			}, {
  				pathPart: "roles",
				methods: {
  					GET: {
						lambdaIntegration: "get_roles",
						parameters: {
							authorization: "NONE",
						}
					},
  					OPTIONS: {
  						optionsIntegration: true,
  						parameters: {
	  						authorization: "NONE"
						}
  					}
  				}
  			}, {
  				pathPart: "sts",
				methods: {
  					GET: {
						lambdaIntegration: "get_sts",
						parameters: {
							authorization: "NONE"
						}
					},
  					OPTIONS: {
  						optionsIntegration: true,
  						parameters: {
	  						authorization: "NONE"
						}
  					}
  				}
  			}, {
  				pathPart: "styx",
				methods: {
  					POST: {
						lambdaIntegration: "styx_broker",
						parameters: {
							authorization: "NONE"
						}
					},
  					OPTIONS: {
  						optionsIntegration: true,
  						parameters: {
	  						authorization: "NONE"
						}
  					}
  				}
  			}]
  		}
  	}),
	'api_gateway_addons.tf.json': {
		resource: {
			aws_api_gateway_account: {
				styx_azuread: {
					cloudwatch_role_arn: "${aws_iam_role.styx_azuread-apigateway_cloudwatch.arn}"
				}
			}
		},
		output: {
			api_gateway_acs_url: {
				value: "${aws_api_gateway_deployment.styx_azuread.invoke_url}acs"
			}
		}
	},
	'cloudfront.tf.json': {
		resource: {
			aws_cloudfront_origin_access_identity: {
				styx_azuread: {
					comment: "OAI for Styx AzureAD",
				},
			},
			aws_cloudfront_distribution: {
				styx_azuread: {
					comment: "styx_azuread",
					enabled: true,
					is_ipv6_enabled: false,
					default_root_object: "index.html",
					logging_config: {
						include_cookies: false,
						bucket: "${aws_s3_bucket.logs.bucket_domain_name}",
						prefix: "cloudfront",
					},
					origin: [{
						domain_name: "${aws_s3_bucket.content.bucket_regional_domain_name}",
						origin_id: "static",

						s3_origin_config: {
							origin_access_identity: "${aws_cloudfront_origin_access_identity.styx_azuread.cloudfront_access_identity_path}",
						}
					}, {
						domain_name: "${aws_api_gateway_rest_api.styx_azuread.id}.execute-api.us-west-2.amazonaws.com",
						origin_path: "/v1",
						origin_id: "apigateway",

						custom_origin_config: {
							http_port: 80,
							https_port: 443,
							origin_protocol_policy: 'https-only',
							origin_ssl_protocols: ['TLSv1.2']
						}
					}],
					default_cache_behavior: {
						allowed_methods: ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"],
						cached_methods: ["GET", "HEAD"],
						target_origin_id: "static",
						forwarded_values: {
							query_string: false,
							headers: ["Origin","Access-Control-Allow-Origin","Access-Control-Request-Method","Access-Control-Request-Headers"],
							cookies: {
								forward: "none",
							}
						},
						viewer_protocol_policy: "redirect-to-https",
						min_ttl: 0,
						max_ttl: 300,
						default_ttl: 0,
					},
					ordered_cache_behavior: [{
						path_pattern: "/acs",
						allowed_methods: ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"],
						cached_methods: ["GET", "HEAD"],
						target_origin_id: "apigateway",
						forwarded_values: {
							query_string: false,
							headers: ["Origin","Access-Control-Allow-Origin","Access-Control-Request-Method","Access-Control-Request-Headers"],
							cookies: {
								forward: "all",
							}
						},
						viewer_protocol_policy: "redirect-to-https",
						min_ttl: 0,
						max_ttl: 300,
						default_ttl: 0,
					}, {
						path_pattern: "/styx",
						allowed_methods: ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"],
						cached_methods: ["GET", "HEAD"],
						target_origin_id: "apigateway",
						forwarded_values: {
							query_string: false,
							headers: ["Origin","Access-Control-Allow-Origin","Access-Control-Request-Method","Access-Control-Request-Headers"],
							cookies: {
								forward: "all",
							}
						},
						viewer_protocol_policy: "redirect-to-https",
						min_ttl: 0,
						max_ttl: 300,
						default_ttl: 0,
					}, {
						path_pattern: "/roles",
						allowed_methods: ["GET", "HEAD", "OPTIONS"],
						cached_methods: ["GET", "HEAD"],
						target_origin_id: "apigateway",
						forwarded_values: {
							query_string: false,
							headers: ["Origin","Access-Control-Allow-Origin","Access-Control-Request-Method","Access-Control-Request-Headers"],
							cookies: {
								forward: "all",
							}
						},
						viewer_protocol_policy: "redirect-to-https",
						min_ttl: 0,
						max_ttl: 300,
						default_ttl: 0,
					}, {
						path_pattern: "/sts",
						allowed_methods: ["GET", "HEAD", "OPTIONS"],
						cached_methods: ["GET", "HEAD"],
						target_origin_id: "apigateway",
						forwarded_values: {
							query_string: true,
							headers: ["Origin","Access-Control-Allow-Origin","Access-Control-Request-Method","Access-Control-Request-Headers"],
							cookies: {
								forward: "all",
							}
						},
						viewer_protocol_policy: "redirect-to-https",
						min_ttl: 0,
						max_ttl: 300,
						default_ttl: 0,
					}, {
						path_pattern: "/console",
						allowed_methods: ["GET", "HEAD", "OPTIONS"],
						cached_methods: ["GET", "HEAD"],
						target_origin_id: "apigateway",
						forwarded_values: {
							query_string: true,
							headers: ["Origin","Access-Control-Allow-Origin","Access-Control-Request-Method","Access-Control-Request-Headers"],
							cookies: {
								forward: "all",
							}
						},
						viewer_protocol_policy: "redirect-to-https",
						min_ttl: 0,
						max_ttl: 300,
						default_ttl: 0,
					}],
					price_class: "PriceClass_100",
					viewer_certificate: {
						cloudfront_default_certificate: true,
					},
					[if settings.use_waf == true then 'web_acl_id' else null]: "${aws_wafv2_web_acl.backend.arn}",
					restrictions: {
						geo_restriction: {
							restriction_type: "none",
						}
					}
				}
			}
		},
		output: {
			azure_ad_acs_url: {
				value: "https://${aws_cloudfront_distribution.styx_azuread.domain_name}/acs"
			},
			azure_ad_redirect_url: {
				value: "https://${aws_cloudfront_distribution.styx_azuread.domain_name}/styx"
			},
		}
	},
	'cloudwatch-api-gateway-role.tf.json': {
		resource: iam.iam_role(
			"styx_azuread-apigateway_cloudwatch",
			"Allow APIGateway to write to CloudWatch Logs",
			{},
	        {
	        	CloudWatchPut: [{
	        		Sid: "logs",
		            Effect: "Allow",
		            Action: [
		                "logs:CreateLogGroup",
		                "logs:CreateLogStream",
		                "logs:DescribeLogGroups",
		                "logs:DescribeLogStreams",
		                "logs:PutLogEvents",
		                "logs:GetLogEvents",
		                "logs:FilterLogEvents"
		            ],
		            Resource: "arn:aws:logs:*"
	        	}]
	        },
			[{
				Effect: "Allow",
				Principal: {
					Service: "apigateway.amazonaws.com"
				},
				Action: "sts:AssumeRole"
			}]
		)
	},
	'cognito.tf.json':: cognito.saml_backed_identity_pool(
		"azure_styx",
		{
			IDPSignout: "false",
			MetadataURL: "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/federationmetadata/2007-06/federationmetadata.xml?appid=${azuread_application.styx.application_id}"
		},
		"https://${aws_cloudfront_distribution.styx_azuread.domain_name}/acs",
		false
	),
	'data.tf.json': {
		data: {
			aws_caller_identity: {
				current: {}
			}
		}
	},
	'dynamodb.tf.json': {
		resource: {
			aws_dynamodb_table: {
				acs_assertions: {
					name: "acs_assertions",
					billing_mode: "PAY_PER_REQUEST",
					hash_key: "key",
					range_key: "ip",

					attribute: [{
						name: "key",
						type: "S"
					}, {
						name: "ip",
						type: "S"
					}],

					ttl: {
						attribute_name: "expires",
						enabled: true
					}
				}
			}
		}
	},
	'iam.tf.json': {
		resource: {
			aws_iam_saml_provider: {
				styx: {
					name: "styx",
					saml_metadata_document: "${data.template_file.metadata_template.rendered}"
				}
			}
		}
	},
	'kms.tf.json': {
		data: {
			aws_kms_public_key: {
				saml: {
					key_id: "${aws_kms_key.saml.arn}"
				}
			}
		},
		resource: {
			aws_kms_key: {
				saml: {
					description: "SAML signing key",
					deletion_window_in_days: 7,
					key_usage: "SIGN_VERIFY",
					customer_master_key_spec: "RSA_2048",
					policy: std.manifestJsonEx({
						Version: "2012-10-17",
						Id: "kms-styx-policy",
						Statement: [{
							Sid: "Enable IAM policies",
							Effect: "Allow",
							Principal: {
								AWS: "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
							},
							Action: "kms:*",
							Resource: "*"
						}]
					}, '')
				}
			},
			local_file: {
				styx_der: {
					content_base64: "${data.aws_kms_public_key.saml.public_key}",
					filename: "%s/styx.der" % sonnetry.path()
				}
			}
		}
	},
	'lambda-acs_parser.tf.json': lambda.lambda_function("acs_parser", {
		handler: "main.main",
		timeout: 3,
		memory_size: 128,

		publish: true,

		environment:: {
			variables: {}
		},
	}, {
		statement: [{
			Effect: "Allow",
			Action: "dynamodb:PutItem",
			Resource: "${aws_dynamodb_table.acs_assertions.arn}"
		}]
	}),
	'lambda-get_console.tf.json': lambda.lambda_function("get_console", {
		handler: "main.main",
		timeout: 3,
		memory_size: 128,

		publish: true,

		environment:: {
			variables: {}
		},
	}, {
		statement: [{
			Effect: "Allow",
			Action: "dynamodb:GetItem",
			Resource: "${aws_dynamodb_table.acs_assertions.arn}"
		}]
	}),
	'lambda-get_roles.tf.json': lambda.lambda_function("get_roles", {
		handler: "main.main",
		timeout: 3,
		memory_size: 128,

		publish: true,

		environment:: {
			variables: {}
		},
	}, {
		statement: [{
			Effect: "Allow",
			Action: "dynamodb:GetItem",
			Resource: "${aws_dynamodb_table.acs_assertions.arn}"
		}]
	}),
	'lambda-get_sts.tf.json': lambda.lambda_function("get_sts", {
		handler: "main.main",
		timeout: 3,
		memory_size: 128,

		publish: true,

		environment:: {
			variables: {}
		},
	}, {
		statement: [{
			Effect: "Allow",
			Action: "dynamodb:GetItem",
			Resource: "${aws_dynamodb_table.acs_assertions.arn}"
		}]
	}),
	'lambda-federation_cors.tf.json': lambda.lambda_function("federation_cors", {
		provider: "aws.us-east-1",
		handler: "main.main",
		timeout: 3,
		memory_size: 128,

		publish: true,

		environment:: {
			variables: {}
		},
	}, {
		statement: []
	}),
	'lambda-styx_broker.tf.json': lambda.lambda_function("styx_broker", {
		handler: "main.main",
		timeout: 30,
		memory_size: 256,

		publish: true,

		environment: {
			variables: {
				APPLICATION_ID: "${azuread_application.styx.application_id}",
				TENANT_ID: "${data.azuread_client_config.current.tenant_id}",
				SECRET_ID: "${aws_secretsmanager_secret.styx_sp_password.id}",
				KMS_KEY_ID: "${aws_kms_key.saml.arn}",
				// KMS_PUBKEY: "${data.aws_kms_public_key.saml.public_key}"
				KMS_PUBKEY: "${data.local_file.saml_certificate.content}",
				CLOUDFRONT_DOMAIN: "${aws_cloudfront_distribution.styx_azuread.domain_name}",
				USE_STYX_VIEW: settings.use_styx_view
			}
		},
	}, {
		statement: [{
			Effect: "Allow",
			Action: "secretsmanager:GetSecretValue",
			Resource: "${aws_secretsmanager_secret.styx_sp_password.arn}"
		}, {
			Effect: "Allow",
			Action: [
				"kms:GetPublicKey",
				"kms:Sign"
			],
			Resource: "${aws_kms_key.saml.arn}"
		}, {
			Effect: "Allow",
			Action: "dynamodb:PutItem",
			Resource: "${aws_dynamodb_table.acs_assertions.arn}"
		}]
	}),
	'null_resource.tf.json': {
		data: {
			local_file: {
				saml_certificate: {
					depends_on: ["null_resource.openssl_generate_cert_from_kms_pubkey"],
					filename: "%s/saml_certificate.der.asc" % sonnetry.path()
				}
			}
		},
		resource: {
			null_resource: {
				openssl_generate_cert_from_kms_pubkey: {
					depends_on: ["local_file.styx_der"],

					provisioner: [{
						"local-exec": {
							command: "node %s/bin/createCertificate.js generate \"%s\" %s ${local_file.styx_der.filename} %s/saml_certificate.der.asc" % [sonnetry.path(), settings.cert_subject, settings.cert_validity_years, sonnetry.path()]
						}
					}],

					triggers: {
						pubkey:: "${data.aws_kms_public_key.saml.public_key}",
						always: "${timestamp()}"
					}
				},
			}
		}
	},
	'provider.tf.json': {
		terraform: {
			required_providers: {
				archive: {
					source: "hashicorp/archive",
					version: "~> 2.2.0"
				},
				aws: {
					source: "hashicorp/aws",
					version: "~> 4.17.1"
				},
				azuread: {
					source: "hashicorp/azuread",
					version: "~> 2.22.0"
				}
			}
		},
		provider: [{
			aws: {
				region: "us-west-2"
			}
		}, {
			aws: {
				alias: "us-east-1",
				region: "us-east-1"
			}
		}, {
			archive: {}
		}, {
			azuread: {
				tenant_id: settings.tenant_id
			}
		}]
	},
	's3.tf.json': {
		resource: {
			aws_s3_bucket: {
				content: {
					bucket_prefix: "styx-azuread-content-",
					force_destroy: true
				},
				logs: {
					bucket_prefix: "styx-azuread-logs-",
					acl: "log-delivery-write",
					force_destroy: true
				}
			},
			null_resource: {
				s3_sync_content: {
					provisioner: [{
						"local-exec": {
							command: "aws s3 sync %s/site-content/ s3://${aws_s3_bucket.content.id}" % sonnetry.path()
						}
					}],

					triggers: {
						always: "${timestamp()}"
					}
				}
			}
		},
		output: {
			s3_content_sync_command: {
				value: "aws s3 sync %s/site-content/ s3://${aws_s3_bucket.content.id}" % sonnetry.path()
			}
		}
	},
	's3_policies.tf.json': {
		data: {
			aws_iam_policy_document: {
				s3_content: {
					statement: {
						actions: ["s3:GetObject"],
						resources: ["${aws_s3_bucket.content.arn}/*"],
						principals: {
							type: "AWS",
							identifiers: ["${aws_cloudfront_origin_access_identity.styx_azuread.iam_arn}"]
						}
					}
				}
			}
		},
		resource: {
			aws_s3_bucket_policy: {
				s3_content: {
					bucket: "${aws_s3_bucket.content.id}",
					policy: "${data.aws_iam_policy_document.s3_content.json}"
				}
			}
		}
	},
	'secrets_manager.tf.json': {
		resource: {
			aws_secretsmanager_secret: {
				styx_sp_password: {
					name: "styx_sp_password",
					recovery_window_in_days: 0
				}
			},
			aws_secretsmanager_secret_version: {
				styx_sp_password: {
					secret_id: "${aws_secretsmanager_secret.styx_sp_password.id}",
					secret_string: "${azuread_service_principal_password.styx.value}"
				}
			}
		}
	},
	'templates.tf.json': {
		data: {
			template_file: {
				metadata_template: {
					template: "${file(\"%s/templates/provider_metadata.xml.tpl\")}" % sonnetry.path(),

					vars: {
						certificate: "${data.local_file.saml_certificate.content}",
						entity: "https://${aws_cloudfront_distribution.styx_azuread.domain_name}/"
					}
				}
			}
		}
	},
	'azure-styx.tf.json': {
		data: {
			azuread_client_config: {
				current: {}
			},
			azuread_application_published_app_ids: {
				well_known: {}
			}
		},
		resource: {
			azuread_application: {
				styx: {
					display_name: "River Styx",
					logo_image: "${filebase64(\"%s/logo.png\")}" % sonnetry.path(),
					owners: ["${data.azuread_client_config.current.object_id}"],
					sign_in_audience: "AzureADMyOrg",

					feature_tags: {
						gallery: false,
						enterprise: true,
						custom_single_sign_on: false
					},

					identifier_uris: ["api://${aws_cloudfront_distribution.styx_azuread.domain_name}"],

					group_membership_claims: ["SecurityGroup"],

					optional_claims: {
						saml2_token: [{
							additional_properties: ["emit_as_roles"],
							essential: true,
							name: "groups"
						}]
					},

					required_resource_access: {
						resource_app_id: "${azuread_service_principal.msgraph.object_id}",

						resource_access: [{
							id: "${azuread_service_principal.msgraph.app_role_ids[\"User.Read.All\"]}",
							type: "Role"
						}, {
							id: "${azuread_service_principal.msgraph.app_role_ids[\"GroupMember.Read.All\"]}",
							type: "Role"
						}, {
							id: "${azuread_service_principal.msgraph.oauth2_permission_scope_ids[\"User.ReadWrite\"]}",
							type: "Scope"
						}]
					},

					web: {
						redirect_uris: ["https://${aws_cloudfront_distribution.styx_azuread.domain_name}/styx"]
					}
				}
			},
			azuread_app_role_assignment: {
				styx_group_read: {
					app_role_id: "${azuread_service_principal.msgraph.app_role_ids[\"GroupMember.Read.All\"]}",
					resource_object_id: "${azuread_service_principal.msgraph.object_id}",
					principal_object_id: "${azuread_service_principal.styx.object_id}",
				},
				styx_user_read: {
					app_role_id: "${azuread_service_principal.msgraph.app_role_ids[\"User.Read.All\"]}",
					resource_object_id: "${azuread_service_principal.msgraph.object_id}",
					principal_object_id: "${azuread_service_principal.styx.object_id}",
				}
			},
			azuread_service_principal: {
				msgraph: {
					application_id: "${data.azuread_application_published_app_ids.well_known.result.MicrosoftGraph}",
					use_existing: true
				},
				styx: {
					description: "Styx group claim broker",
					application_id: "${azuread_application.styx.application_id}",
					owners: ["${data.azuread_client_config.current.object_id}"],
					app_role_assignment_required: false,

					feature_tags: {
						gallery: false,
						enterprise: true,
						custom_single_sign_on: true
					},

					preferred_single_sign_on_mode: "saml"
				}
			},
			azuread_service_principal_password: {
				styx: {
					service_principal_id: "${azuread_service_principal.styx.id}"
				}
			}
		},
		output: {
			azure_saml_metadata_url: {
				value: "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/federationmetadata/2007-06/federationmetadata.xml?appid=${azuread_application.styx.application_id}"
			}
		}
	},
	'trust_policy.tf.json': {
		resource: {
			local_file: {
				trust_policy: {
					filename: "%s/trust_policy.json" % sonnetry.path(),
					content: std.manifestJsonEx({
					    Version: "2012-10-17",
					    Statement: [
					        {
					            Effect: "Allow",
					            Principal: {
					                Federated: "arn:aws:iam::<account_id>:saml-provider/styx"
					            },
					            Action: "sts:AssumeRoleWithSAML",
					            Condition: {
					                StringEquals: {
					                    'saml:aud': [
					                        "https://${aws_cloudfront_distribution.styx_azuread.domain_name}/styx",
					                        "https://signin.aws.amazon.com/saml"
					                    ]
					                }
					            }
					        }
					    ]
					}, "\t")
				}
			}
		}
	},
	[if settings.use_waf == true then 'waf.tf.json' else null]: {
		resource: {
			aws_wafv2_web_acl: {
				backend: {
					provider: "aws.us-east-1",
					name: "styx_azuread_waf",
					description: "WAF for Styx AzureAD",
					scope: "CLOUDFRONT",

					default_action: {
						allow: {}
					},

					rule: [{
						name: "aws_core_ruleset",
						priority: 1,

						override_action: {
							count: {}
						},

						statement: [{
							managed_rule_group_statement: {
								name: "AWSManagedRulesCommonRuleSet",
								vendor_name: "AWS"
							}
						}],

						visibility_config: [{
							cloudwatch_metrics_enabled: false,
							metric_name: "cloudhsm_backed_waf-core_ruleset",
							sampled_requests_enabled: false
						}]
					}],

					visibility_config: [{
						cloudwatch_metrics_enabled: false,
						metric_name: "cloudhsm_backed_waf",
						sampled_requests_enabled: false
					}]
				}
			}
		}
	}
}