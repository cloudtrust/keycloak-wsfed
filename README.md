# WS-Federation for Keycloak

The purpose of this module is to support the 
[WS-FED protocol](http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html) 
in [Keycloak](https://www.keycloak.org/). Only Web (Passive) requestors are supported, as defined in 
[section 13 of the specification](http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html#_Toc223175002).
It should be noted that the optional elements of the protocol (attribute services and pseudonym services) are not 
currently supported. However, in its current capacity the WS-Fed protocol can be used for communication with:

* Keycloak clients (WS Resources), with Keycloak acting as an IdP/STS.
* Other IdPs, with Keycloak acting as an Identity Broker.

The WS-Fed protocol does not specify the format of the tokens, but this module supports SAML 2.0 and SAML 1.1 tokens 
for its operations. 

This module is currently working on 7.0.0 (check tags for compatibility with previous Keycloak versions)

## How to Install

### Copy files

This is an example with Keycloak available at /opt/keycloak

```Bash
#Create layer in keycloak setup
install -d -v -m755 /opt/keycloak/modules/system/layers/wsfed -o keycloak -g keycloak

#Setup the module directory
install -d -v -m755 /opt/keycloak/modules/system/layers/wsfed/com/quest/keycloak-wsfed/main/ -o keycloak -g keycloak

#Install jar
install -v -m0755 -o keycloak -g keycloak -D target/keycloak-wsfed-7.0.0.jar /opt/keycloak/modules/system/layers/wsfed/com/quest/keycloak-wsfed/main/

#Install module file
install -v -m0755 -o keycloak -g keycloak -D module.xml /opt/keycloak/modules/system/layers/wsfed/com/quest/keycloak-wsfed/main/

```

### Enable module & load theme

__layers.conf__

```Bash
layers=keycloak,wsfed
```

__standalone.xml__

```xml
...
<web-context>auth</web-context>
<providers>
    <provider>module:com.quest.keycloak-wsfed</provider>
    ...
</providers>
...
<theme>
    <modules>
            <module>
                    com.quest.keycloak-wsfed
            </module>
    </modules>
    ...
</theme>
...
```

After that you need to set the Admin Console theme to `wsfed` in the master realm and in the realm with the WS-FED 
clients, then restart Keycloak.

## How to use

### How to setup a Keycloak client

In this section we will explain how to setup a Keycloak client. We will use two types of servers to act as WS-Fed 
Resources (Service Providers) for our example: The first is an
[IdP test client](https://github.com/cloudtrust/idp-test-client), while the second is Sharepoint 2013.

#### Creating a client

A WS-Fed client is added as any other: go to the **Clients** menu item and create a new client, making sure that in the
"Add Client" screen, the **client protocol**, is `wsfed`. Normally, any value can be used for the **Client ID**, as long
as it is shared with the WS-Fed resource.

A small side note: in WS-Fed parlance, the actual term for **Client ID** is _Realm_, and is the value shared in the
`wtrealm` URI query. This can obviously lead to confusion when working with Keycloak.

##### Settings tab

The values **Name**, **Description**, **Enabled**, **Consent required** and **Client template** are the same general
parameters for clients as described in the
[Keycloak documentation for SAML clients](https://www.keycloak.org/docs/latest/server_admin/index.html#saml-clients).

The following set of options are protocol specific: the **SAML Assertion Token Format** option allows the use of
`SAML 1.1` or `SAML 2.0` tokens. The **Front Channel Logout** option determines if the logout requires a browser redirect
to the client (for `true`) or if the server performs a background invocation (for`false`). The **Encrypt Assertions**
option allows the SAML Assertion to be encrypted with the client's public key.

The last set of options concern the URIs of the client. The values **Root URL**, **Valid Redirect URIs** and **Base
URL** are the same as those described in the
[Keycloak documentation for SAML clients](https://www.keycloak.org/docs/latest/server_admin/index.html#saml-clients).

##### SAML Keys tab

This tab is only available if the **Encrypt Assertions** setting was enabled in the Settings tab. As with the SAML
client, it is possible to generate and export a key pair, or to import a certificate from a JKS file, PKSC12 file or a
PEM certificate file. However, the imported certificate MUST be RSA, or there will be an error during runtime.

##### Mappers tab

Mappers are generally handled in the same way as described as described in the 
[Keycloak documentation on mappers](https://www.keycloak.org/docs/latest/server_admin/index.html#_protocol-mappers).

Mappers are equivalent to those from the SAML client, however, there is an extra mapper present
in the WS-Fed SAML mappers: a `SAML javascript mapper`. Its use is almost analog to the OIDC script mapper:
the [nashorn javascript engine](https://docs.oracle.com/javase/10/nashorn/introduction.htm#JSNUG136) is used to
evaluate the input script, and the last statement is the value that will be returned in the SAML attribute. The
sole difference to the OIDC variant is that the `SAML javascript mapper` can handle Iterables or arrays as a return
value: the result will either be multiple attributes, or a single attribute with a grouped value, depending on the
value of the **Single Group Attribute** option.

##### Installation tab

The installation tab gives access to the WS-Fed metadata, which can be used to configure the WS-Fed resource. This
information can also be accessed at `http[s]://<hostname>:<port>/auth/realms/<realm>/protocol/wsfed/descriptor`.

#### Example: configuration with the IdP test client

For this example we will be running Keycloak with the WS-Fed module installed on localhost:8080 and the
[IdPTestClient](https://github.com/cloudtrust/idp-test-client) on localhost:7000.

##### Realm setup

Create a realm `TestRealm`, with the roles `user`, `testUser` and `groupUser` in addition to Keycloak's default roles.
In this realm, create a user with the following characteristics:

* **Username**: `test.testuser`
* **Email**: `test.testuser@testrealm.io`
* **Firstname**: `test`
* **Lastname**: `testuser`
* **User Enabled**: `on`
* **Email Verified**: `off`

In **credentials**, set the password to `password` (with **Temporary** set to `off`). In **Role Mappings**, and the roles
`user` and `testUser`.

##### Client setup

Go to the **Clients** menu, and create a new client. In the "Add Client" page screen choose `wsfed` for the
**client protocol**, `WSFedTestClient` for the **Client ID** and save.

In the **Settings** tab, set the **Valid Redirect URIs** to `http://localhost:7000/*`, leave the rest of the values
unchanged and save.

In the **Mappers** tab, create a new mapper. For **Mapper Type** select `SAML Role list`, and then set the **Name** to
`SAML Role mapper` and the **SAML Attribute Nameformat** to `Basic` before saving.

Go to the **Installation** tab, and select `WSFed Metadata IDP Descriptor`, the values will be useful for the next step.

##### IdPTestClient setup

Clone the [idp-test-client](https://github.com/cloudtrust/idp-test-client) repository, and follow the instructions to
build the jar.

Create a new certif.cer file. The format of the file should be the following:

```
-----BEGIN CERTIFICATE-----
CERTIFICATE_VALUE
-----END CERTIFICATE-----
```

With `CERTIFICATE_VALUE` being the value from the "X509Certificate" field from the `WSFed Metadata IDP Descriptor`.

Create a keystore with the command:

```
keytool -importcert -file certif.cer -keystore localstore.jks -alias "TestRealm"
```

And choose `localpass` as the password (make sure that the java keytool is on the PATH).

Create the following `fediz-config.xml` file for the ws-fed configuration of the IdPTestClient:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FedizConfig>
    <contextConfig name="/">
        <audienceUris>
            <audienceItem>http://localhost:7000/</audienceItem>
        </audienceUris>
        <certificateStores>
            <trustManager>
                <keyStore file="file:///absolute/path/to/localstore.jks" password="localpass" type="JKS" />
            </trustManager>
        </certificateStores>
        <trustedIssuers>
            <issuer certificateValidation="PeerTrust" />
        </trustedIssuers>
        <protocol xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="federationProtocolType" version="1.2">
            <issuer>http://localhost:8080/auth/realms/TestRealm/protocol/wsfed</issuer>
            <realm>WSFedTestClient</realm>
            <reply>/j_spring_fediz_security_check</reply>
        </protocol>
        <logoutURL>/wsfedLogout</logoutURL>
        <logoutRedirectTo>/performLogout</logoutRedirectTo>
    </contextConfig>
</FedizConfig>
```

Note that the "issuer" is the value in "EndpointReference" from the `WSFed Metadata IDP Descriptor`.

Then, making sure that the jar and the fediz-config.xml are in a same directory, run:

```
java -jar IdPTestClient.jar --fediz.configFilePath=fediz_config.xml
```

The website at localhost:7000 will have the option to login with WS-Fed.

#### Example: configuration in Sharepoint 2013

The realm setup for this example is the same as the one for the IdPTestClient setup.

Go to the **Clients** menu, and create a new client. In the "Add Client" page screen choose `wsfed` for the
**client protocol**. For Sharepoint, the **Client ID** must be in the urn format, so we will have
`urn:testsharepoint:wsfed` (with an incorrect format, Sharepoint will throw an Unknown SPRequest error). Save the
values.

Sharepoint will only accept HTTPS connections (this is also true for the Keycloak endpoint), and SAML 1.1 tokens.
Imagining that Sharepoint is also on the localhost, we have the following values in the **Settings** tab:

* **SAML Assertion Token Format**: `SAML1.1`
* **Valid Redirect URIs**: `https://localhost/*`

In the **Mappers** tab create the following mappers:

1. **Name**: `SAML role list`, **Mapper Type**: `SAML Role List`, **Role attribute name**: `Role`, **SAML Attribute
NameFormat**: `Basic`
2. **Name**: `SAML upn`, **Mapper Type**: `SAML User Property`, **Property**: `username`, **SAML Attribute Name**:
`upn`, **SAML Attribute NameFormat**: `Basic`
3. **Name**: `SAML email`, **Mapper Type**: `SAML User Property`, **Property**: `email`, **SAML Attribute Name**:
`emailaddress`, **SAML Attribute NameFormat**: `Basic`

In the **Installation** tab, copy the content of the "X509Certificate" field from the `WSFed Metadata IDP Descriptor` to
a new certif.cer file.

Next is setting up Sharepoint to use the Keycloak server. The following
[guide to configure ADFS with Sharepoint](https://sharepointobservations.wordpress.com/2013/08/19/sharepoint-2013-how-to-install-and-configure-adfs-2-0/)
describes the steps from the **Configure SharePoint Web Application** section with pictures. The basic steps are the
following:

**_Step 1_**: Run the following powershell script as administrator from the SharePoint 2013 Management Shell:

```powershell
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("Path\To\certif.cer")

### This section should only be necessary for self-signed certificates ###
 $tokenSigningCertificateName = "Keycloak Cloudtrust TestRealm"
 if (Get-SPTrustedRootAuthority -Identity $tokenSigningCertificateName -ea "silentlycontinue") {
     Write-Host "Signing certificate already trusted."
   }
   else {
     Write-Host "Adding signing certificate to SharePoint trusts."
     New-SPTrustedRootAuthority -Name $tokenSigningCertificateName -Certificate $cert
   }
### end section ###

 $idClaim = New-SPClaimTypeMapping -IncomingClaimType "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" -IncomingClaimTypeDisplayName "Email address" -SameAsIncoming
 $map1 = New-SPClaimTypeMapping -IncomingClaimType "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" -IncomingClaimTypeDisplayName "UPN" -SameAsIncoming
 $map2 = New-SPClaimTypeMapping -IncomingClaimType "http://schemas.microsoft.com/ws/2008/06/identity/claims/role" -IncomingClaimTypeDisplayName "Role" -SameAsIncoming

 $realm = "urn:testsharepoint:wsfed"
 $signinurl = "https://localhost:8443/auth/realms/TestRealm/protocol/wsfed"
 $ap = New-SPTrustedIdentityTokenIssuer -Name "KeycloakTestRealm" -Description "Trust to Keycloak" -Realm $realm -ImportTrustCertificate $cert -ClaimsMappings $map1, $map2, $idClaim  -SignInUrl $signinurl -IdentifierClaim $idClaim.InputClaimType
 $ap.UseWReplyParameter = $true
 $ap.Update()
```

Note that the `$signinurl` is the value in "EndpointReference" from the `WSFed Metadata IDP Descriptor`.

**_Step 2_**: With Sharepoint 2013 Central Administration, go to **Manage Web Applications** > **Sharepoint - localhost:443** >
**Authentication Providers** > **default**, and under "Trusted Identity provider" select `KeycloakTestRealm`.

When going to your Sharepoint at https://localhost, you will now have the option to log in with `KeycloakTestRealm`

### How to setup a Keycloak identity broker

We will explain here how to setup identity brokering using two instances of Keycloak: one as identity broker, and the
second as external IdP. Naturally, for this to work, the WS-Fed module must be installed on both instances of Keycloak.

#### Setting up the identity broker

Go to the **Identity Providers** menu item and create a new identity provider selecting `WS-Fed` from the list.

The first part of the settings are the general IdP settings, described in the
[Keycloak documentation](https://www.keycloak.org/docs/latest/server_admin/index.html#_general-idp-config). The only
things of note are that:
 
 * The **alias** can be set to any value, it serves as the identifier of the identity broker - external IdP link.
 * The **First Login Flow** should be set to `first broker login` in most cases. This means that Keycloak will create
 a local registration of any external users at first login, create a link between the local and external user for
 subsequent logins.

The endpoint information from the external IdP must be setup in the `WS-Fed configuration` section. For a Keycloak
external IdP, this can be obtained at the address:

 ```
 http[s]://{host:port}/auth/realms/{realm-name}/protocol/wsfed/descriptor
 ```

This will give the following information:

 * **Single Sign-On Service URL** (in the `PassiveRequestorEndpoint` section)
 * **Single Logout Service URL** (in the `PassiveRequestorEndpoint` section, the same as the Single Sign-On Service URL)
 * **Validating X509 Certificates** (in the `X509Certificate` tags). This is only used if the **Validate Signature**
 option is set to on (which is recommended).

The remaining options are:

 * **WS-Fed Realm**: This is the name of the client in the Keycloak external IdP. The value is unimportant as long
 as it is the same in both the configuration of the identity broker and the external IdP.
 * **Backchannel Logout**: set to "on" if the external IdP supports the Backchannel logout
 * **Handle Empty Action as wsignoutcleanup1.0**: normally for the clean-up phase of a sign-out, the `wa` action
 must be set to wsignoutcleanup1.0, but with this option activated, an empty `wa` will be considered as a cleanup.

#### Setting up the client (WS Resource)

On the external IdP Keycloak, go to the `Clients` menu item and create a new client, selecting `wsfed` for the **Client
Protocol**. The **Client ID** value must be set to the same value as in the **WS-Fed Realm** value on the Keycloak
identity broker.

In the `Settings` tab, the only important elements to set are:

* the **SAML Assertion Token Format**, which specifies the type of token to use. Currently only SAML 1.1 and 2.0 tokens
are supported.
* the **Valid Redirect URIs** parameter. For a Keycloak identity broker, this value MUST be set to the value of the
**Redirect URI** in the settings tab.

##### Using mappers to automatically get first broker login information

If no mappers are setup, upon the first login using Keycloak as an identity broker, and after authentication with the
external IdP is successful, Keycloak will display a form to get the missing information. The information required will
be: **username**, **email**, **first name** and **last name**. The username will always be set, as Keycloak requires
this information and will use the subject information if necessary, but it is possible to modify it.

However, it is also possible to set this information by passing the information as attributes in the SAML assertion. If
all information is provided, Keycloak will skip the form, and directly create the user. Currently however, this only
works with SAML 1.1 assertions.

To get the information, the following mappers must be created in the client:

* A mapper for the username: Should be of type `SAML User Property`. The **property** should be set to `username`. The
**SAML Attribute Name** MUST be set to `name`.
* A mapper for the email:  Should be of type `SAML User Property`. The **property** should be set to `email`. The
**SAML Attribute Name** MUST be set to `emailaddress`.
* A mapper for the first name:  Should be of type `SAML User Property`. The **property** should be set to `firstName`.
The **SAML Attribute Name** MUST be set to `givenname`.
* A mapper for the last name:  Should be of type `SAML User Property`. The **property** should be set to `lastName`. The
**SAML Attribute Name** MUST be set to `surname`.