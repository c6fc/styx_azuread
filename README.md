# River Styx for Azure AD

River Styx for Azure AD allows organizations to govern access to AWS IAM Roles through Azure AD Group memberships, and provide users a friendly UI to access the console or retrieve STS tokens for each role.

![styx_ui](https://user-images.githubusercontent.com/143415/195136625-eb2fa20b-28ea-437a-8764-f2ad516f4bce.png)

## Installation

To install Styx for Azure AD, you must first install and configure the Azure CLI ('az') with credentials for your target tenant. Once that is ready, use the following to install dependencies and initiate the deployment:
```bash
git clone https://github.com/c6fc/styx_azuread.git
cd styx_azuread

# Edit the settings file to set your tenant id
cp settings.jsonnet.example settings.jsonnet
vim settings.jsonnet

# Install npm dependencies, and start the deployment
npm install
npm run deploy
```

When the automatic provisioning is complete, it's necessary to manually generate a certificate for the Enterprise Application in Azure (Terraform can't do it automatically):

1. Navigate to your tenancy in the Azure Portal
2. Go to Azure Active Directory -> Enterprise applications -> River Styx -> Single sign-on
3. Under card '3 - SAML Certficates', click 'Add a certificate'
4. Accept the defaults ("Sign SAML assertion" and "SHA-256"), click 'New Certificate', and 'Save'.

## Create and populate groups in Azure AD

Groups for Styx must follow a specific naming convention to be recognized by the integration:

```
AWS_123456789012_Developers
     ^ Account       ^ Role name
```

Members of this group would be permitted to assume the role named 'Developers' in account '123456789012'.

1. Navigate to your tenancy in Azure AD
2. Azure Active Directory -> Groups
3. Create a new group using the account id and role name it will govern access to
4. Add users who should be permitted to access this role
5. Navigate to Azure Active Directory -> Enterprise applications -> River Styx -> Users and Groups
6. Click 'Add user/group' and add the group you just created to the application

## Configure destination accounts

### Download the IdP metadata from the deployment account

1. In your deployment account, navigate to the IAM console, and click 'Identity Providers' -> 'styx'
2. Click the 'Download metadata' button, and save the file for later.

### Create the IAM Identity Provider in destination accounts

1. In each destination account, navigate to the IAM console, and click 'Identity Providers'
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

1. Users visit https://myapps.microsoft.com/
2. Click the app shown as 'River Styx'

## Uninstallation

The process to remove Styx for Azure AD is similar to creating, you must first install and configure the Azure CLI ('az') with credentials for your target tenant. Once that is ready, use the following to install dependencies and run the destroy:
```bash
git clone https://github.com/c6fc/styx_azuread.git
cd styx_azuread

# Edit the settings file to set your tenant id
cp settings.jsonnet.example settings.jsonnet
vim settings.jsonnet

# Install npm dependencies, and run the destroy
npm install
npm run destroy
```