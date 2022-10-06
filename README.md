# River Styx for Azure AD

River Styx for Azure AD allows organizations to govern access to AWS IAM Roles through Azure AD Group memberships.

## Installation

1. Clone the repo, install dependencies, configure 'az' with credentials.
2. Copy `settings.jsonnet.example` to `settings.jsonnet`, and update your `tenant_id`
3. Run `npx sonnetry apply terraform.jsonnet`

When the automatic provisioning is complete, it's necessary to manually generate a certificate for the Enterprise Application in Azure (Terraform can't do it automatically):

1. Navigate to your tenancy in Azure AD
2. Azure Active Directory -> Enterprise applications -> Styx -> Single sign-on
3. Under card '3 - SAML Certficates', click 'Add a certificate'
4. Accept the defaults ("Sign SAML assertion" and "SHA-256"), click 'New Certificate', and 'Save'.

## Create and populate groups in Azure AD

Groups for Styx must follow a specific naming convention to be recognized by the integration:

```
AWS_123456789012_Developers
     ^ Account       ^ Role name
```

Members of this group would be permitted to assume the role named 'Developers' in account '123456789012'

1. Navigate to your tenancy in Azure AD
2. Azure Active Directory -> Groups
3. Create a new group using the account id and role name it will govern access to
4. Add users who should be permitted to access this role
5. Navigate to Azure Active Directory -> Enterprise applications -> Styx -> Users and Groups
6. Click 'Add user/group' and add the group you just created to the application (optional)

## Configure destination accounts

### Download the IdP metadata from the deployment account

1. Navigate to the IAM console, and click 'Identity Providers' -> Styx
2. Click the 'Download metadata' button, and save the file for later.

### Create the IAM Identity Provider in destination accounts

1. Navigate to the IAM console, and click 'Identity Providers'
2. Click 'Add Provider'
3. Use the provider type of 'SAML', enter the provider name as 'styx' (case sensitive), and upload the metadata document downloaded earlier.
4. Click 'Add provider'

## Create new destination roles

Once each destination account has the identity provider configured, you must then create any destination role that you plan to use.

1. Navigate to the IAM console, and click 'Roles'
2. Click 'Create Role'
3. Select 'Custom Trust Policy' as the trusted entity type, and paste the contents of the `trust_policy.json` file.
4. Change the line in the trust policy to replace <account_id> with the account id of the account the role is being created in.
5. Click 'next', add the permissions needed for the role, and click 'Next'
6. Give the role a name based on the group you created for it, then click 'Create role'

## Authorize styx to access existing roles (advanced)

This step assumes that you've already created the Azure AD Group associated with the role to be assumed.

1. Open the target role in the AWS Console, click 'Trust relationships', and click 'Edit trust policy'
2. Copy the object inside the 'statement' array from the `trust_policy.json` file, and add it to the statement array of the role's trust policy
3. Click 'Update Policy'

## Test the integration

1. Ensure that your user is a member of one or more role entitlement groups in Azure AD
2. Navigate to your tenancy in Azure AD
3. Azure Active Directory -> Enterprise applications -> Styx -> Single sign-on -> Test this application
4. Ensure the 'Sign in as current user' radio option is selected, then click 'Test sign in'

## How users access River Styx

1. Users visit 'https://myapps.microsoft.com/'
2. Click the app shown as 'styx'