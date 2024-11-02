# PHP OpenID Connect Basic Client
A simple library that allows an application to authenticate a user through the basic OpenID Connect flow. This library
hopes to encourage OpenID Connect use by making it simple enough for a developer with little knowledge of the OpenID
Connect protocol to setup authentication.

## Supported Specifications
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) ([finding the issuer is missing](https://github.com/jumbojett/OpenID-Connect-PHP/issues/2))
- [OpenID Connect RP-Initiated Logout 1.0 - draft 01](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
- [RFC 6749: The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7009: OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)
- [RFC 7636: Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)
- [RFC 7662: OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
- [Draft: OAuth 2.0 Authorization Server Issuer Identifier in Authorization Response](https://tools.ietf.org/html/draft-ietf-oauth-iss-auth-resp-00)

## Tested providers
> Note: This list is not exhaustive. Other generic OIDC providers should work as well.
If you have tested this library with a provider not listed here, please open a PR to add it to the list and add a test configuration (.run directory).

| Provider | Is tested? | Notes                                                         |
|----------|------------|---------------------------------------------------------------|
| Keycloak | ✅          | Client authenticator must be set to "Client id and secret"    |
| Casdoor  | ✅          | Code challenge must be set to S256 or PKCE should be disabled |

## Requirements
1. PHP 8.1+
2. JSON extension
3. MBString extension
4. (Optional) One between GMP or BCMath extension to allow faster cipher key operations
   (for JWT; see [here](https://web-token.spomky-labs.com/introduction/pre-requisite) for more information)

## Install
Install using composer:

```bash
composer require maicol07/oidc-client
```

## Examples
### Example 1: Basic Client
This example uses the Authorization Code flow and will also use PKCE if the OpenID Provider announces it in his
Discovery document. If you are not sure, which flow you should choose: This one is the way to go. It is the most secure
and versatile.

```php
use Maicol07\OpenIDConnect\Client;

$oidc = new Client(
    provider_url: 'https://id.example.com',
    client_id: 'ClientIDHere',
    client_secret: 'ClientSecretHere',
    redirect_uri: 'https://example.com/callback.php',
);
$oidc->authenticate();
$name = $oidc->getUserInfo()->given_name;
```
[See OpenID Connect spec for available user attributes][1]

### Example 2: Dynamic Registration
```php
use Maicol07\OpenIDConnect\Client;

$oidc = new Client(
    provider_url: 'https://id.example.com',
    redirect_uri: 'https://example.com/callback.php',
    client_name: 'My Client',
);

$oidc->register();
[$client_id, $client_secret] = $oidc->getClientCredentials();

// Be sure to add logic to store the client id and client secret
```

### Example 3: Network and Security
You should always use HTTPS for your application. If you are using a self-signed certificate, you can disable the SSL
verification by setting the `verify_ssl` property on the client and, if you have it, set a custom certificate in the `cert_path` property
(this works only if verifySsl is set to false).

You can also setup a proxy via the `http_proxy`.

```php
use Maicol07\OpenIDConnect\Client;

$oidc = new Client(
    provider_url: 'https://id.example.com',
    client_id: 'ClientIDHere',
    client_secret: 'ClientSecretHere',
    redirect_uri: 'https://example.com/callback.php',
    http_proxy: 'http://proxy.example.com:8080',
    cert_path: 'path/to/cert.pem',
    verify_ssl: false
);
```

### Example 4: Implicit flow
> Reference: https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth

The implicit flow should be considered a legacy flow and not used if authorization code grant can be used. Due to its
disadvantages and poor security, the implicit flow will be obsoleted with the upcoming OAuth 2.1 standard. See Example 1
for alternatives.

```php
use Maicol07\OpenIDConnect\Client;
use Maicol07\OpenIDConnect\ResponseType;

$oidc = new Client(
    provider_url: 'https://id.example.com',
    client_id: 'ClientIDHere',
    client_secret: 'ClientSecretHere',
    redirect_uri: 'https://example.com/callback.php',
    response_type: ResponseType::ID_TOKEN,
    allow_implicit_flow: true,
);
$oidc->authenticate();
$sub = $oidc->getUserInfo()->sub;
```

### Example 5: Introspection of an access token
> Reference: https://tools.ietf.org/html/rfc7662

```php
use Maicol07\OpenIDConnect\Client;

$oidc = new Client(
    provider_url: 'https://id.example.com',
    client_id: 'ClientIDHere',
    client_secret: 'ClientSecretHere',
    redirect_uri: 'https://example.com/callback.php'
);

$data = $oidc->introspectToken('an.access-token.as.given');
if (!$data->get('active')) {
    // the token is no longer usable
}
```

### Example 6: PKCE Client
PKCE is already configured and used in most scenarios in Example 1. This example shows you how to explicitly set the Code
Challenge Method in the initial config. This enables PKCE in case your OpenID Provider doesn’t announce support for it
in the discovery document, but supports it anyway.

```php
use Maicol07\OpenIDConnect\Client;
use Maicol07\OpenIDConnect\CodeChallengeMethod;

$oidc = new Client(
    provider_url: 'https://id.example.com',
    client_id: 'ClientIDHere',
    client_secret: 'ClientSecretHere',
    redirect_uri: 'https://example.com/callback.php',
    // for some reason we want to set S256 explicitly as Code Challenge Method
    // maybe your OP doesn’t announce support for PKCE in its discovery document.
    code_challenge_method: CodeChallengeMethod::S256
);

$oidc->authenticate();
$name = $oidc->getUserInfo()->given_name;
```

### Example 7: Token endpoint authentication method
By default, only `client_secret_basic` is enabled on client side which was the only supported for a long time.
Recently `client_secret_jwt` and `private_key_jwt` have been added, but they remain disabled until explicitly enabled.

```php
use Maicol07\OpenIDConnect\Client;
use Maicol07\OpenIDConnect\TokenEndpointAuthMethod;

$oidc = new Client(
    provider_url: 'https://id.example.com',
    client_id: 'ClientIDHere',
    client_secret: 'ClientSecretHere',
    redirect_uri: 'https://example.com/callback.php',
    token_endpoint_auth_methods_supported: [
        TokenEndpointAuthMethod::CLIENT_SECRET_BASIC,
        TokenEndpointAuthMethod::CLIENT_SECRET_JWT,
        TokenEndpointAuthMethod::PRIVATE_KEY_JWT,
    ]
);
```

**Note: A JWT generator is not included in this library yet.**

## Development Environments

Sometimes you may need to disable SSL security on your development systems. You can do it by calling the `verify` method
with the `false` parameter. Note: This is not recommended on production systems.

```php
use Maicol07\OpenIDConnect\Client;

$oidc new Client(
    provider_url: 'https://id.example.com',
    client_id: 'ClientIDHere',
    client_secret: 'ClientSecretHere',
    redirect_uri: 'https://example.com/callback.php',
    verify_ssl: false      
);
```

## Testing
To run the tests, you need to have a running OpenID Connect provider
### Keycloak
1. Run a Keycloak docker container
```bash
docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:25.0.5 start-dev
```
2. Create a realm named `test`
3. Create a client named `test-client` with `confidential` access type
4. Set the `Valid Redirect URIs` to `http://localhost:8080/callback`
5. Set the `Web Origins` to `http://localhost:8080`
6. Set the `Access Type` to `Bearer-only`
7. Set the `Client Authenticator` to `Client id and secret`
8. Set the `Client ID` to `test-client`
9. Set the `Client Secret` to `test-client-secret`
10. Set the `Root URL` to `http://localhost:8080`


### Todo
- Dynamic registration does not support registration auth tokens and endpoints

## Contributing
- Issues and pull requests are welcome.

[1]: https://openid.net/specs/openid-connect-basic-1_0-15.html#id_res
