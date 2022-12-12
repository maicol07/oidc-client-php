# PHP OpenID Connect Basic Client
A simple library that allows an application to authenticate a user through the basic OpenID Connect flow. This library
hopes to encourage OpenID Connect use by making it simple enough for a developer with little knowledge of the OpenID
Connect protocol to setup authentication.

This package is a complete refactor of [JuliusPC/OpenID-Connect-PHP](https://github.com/JuliusPC/OpenID-Connect-PHP).

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

## Requirements
1. PHP 8.1+
2. JSON extension
3. MBString extension
4. (Optional) One between GMP or BCMath extension to allow faster cipher key operations
(for JWT; see [here](https://web-token.spomky-labs.com/introduction/pre-requisite) for more information)

## Install
Install using composer:
```bash
composer require maicol07/oidc-client-php
```

## Examples
### Example 1: Basic Client
This example uses the Authorization Code flow and will also use PKCE if the OpenID Provider announces it in his
Discovery document. If you are not sure, which flow you should choose: This one is the way to go. It is the most secure
and versatile.

```php
use Maicol07\OpenIDConnect\Client;

$oidc = (new Client())
    ->providerUrl('https://id.example.com')
    ->clientId('ClientIDHere')
    ->clientSecret('ClientSecretHere')
$oidc->authenticate();
$name = $oidc->getUserInfo()->given_name;
```
[See OpenID Connect spec for available user attributes][1]

### Example 2: Dynamic Registration
```php
use Maicol07\OpenIDConnect\Client;

$oidc = (new Client())
    ->providerUrl('https://id.example.com')

$oidc->register();
[$client_id, $client_secret] = $oidc->getClientCredentials();

// Be sure to add logic to store the client id and client secret
```

### Example 3: Network and Security
You should always use HTTPS for your application. If you are using a self-signed certificate, you can disable the SSL
verification by calling the `verifySsl` method on the client and, if you have it, set a custom certificate with `certPath` method
(this works only if verifySsl is set to false).

You can also setup a proxy via the `httpProxy`.

```php
use Maicol07\OpenIDConnect\Client;

$oidc = (new Client())
    ->providerUrl('https://id.example.com')
    ->clientId('ClientIDHere')
    ->clientSecret('ClientSecretHere')
    ->httpProxy('http://proxy.example.com:8080')
    ->certPath('path/to/cert.pem')
    ->verifySsl(false)
```

### Example 4: Implicit flow
> Reference: https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth

The implicit flow should be considered a legacy flow and not used if authorization code grant can be used. Due to its
disadvantages and poor security, the implicit flow will be obsoleted with the upcoming OAuth 2.1 standard. See Example 1
for alternatives.

```php
use Maicol07\OpenIDConnect\Client;
use Maicol07\OpenIDConnect\ResponseType;

$oidc = (new Client())
    ->providerUrl('https://id.example.com')
    ->clientId('ClientIDHere')
    ->clientSecret('ClientSecretHere')
    ->responseType(ResponseType::ID_TOKEN)
    ->allowImplicitFlow(true)
$oidc->authenticate();
$sub = $oidc->getUserInfo()->sub;
```

### Example 5: Introspection of an access token
> Reference: https://tools.ietf.org/html/rfc7662

```php
use Maicol07\OpenIDConnect\Client;

$oidc = (new Client())
    ->providerUrl('https://id.example.com')
    ->clientId('ClientIDHere')
    ->clientSecret('ClientSecretHere')

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

$oidc = (new Client())
    ->providerUrl('https://id.example.com')
    ->clientId('ClientIDHere')
    ->clientSecret('ClientSecretHere')
    // for some reason we want to set S256 explicitly as Code Challenge Method
    // maybe your OP doesn’t announce support for PKCE in its discovery document.
    ->codeChallengeMethod(CodeChallengeMethod::S256)

$oidc->authenticate();
$name = $oidc->getUserInfo()->given_name;
```

### Example 7: Token endpoint authentication method
By default, only `client_secret_basic` is enabled on client side which was the only supported for a long time.
Recently `client_secret_jwt` and `private_key_jwt` have been added, but they remain disabled until explicitly enabled.
    
```php
use Maicol07\OpenIDConnect\Client;
use Maicol07\OpenIDConnect\TokenEndpointAuthMethod;

$oidc = (new Client())
    ->providerUrl('https://id.example.com')
    ->clientId('ClientIDHere')
    ->clientSecret('ClientSecretHere')
    ->endpoints(options: [
        'token_endpoint_auth_methods_supported' => [
            TokenEndpointAuthMethod::CLIENT_SECRET_BASIC,
            TokenEndpointAuthMethod::CLIENT_SECRET_JWT,
            TokenEndpointAuthMethod::PRIVATE_KEY_JWT,
        ],
    ]);
```
**Note: A JWT generator is not included in this library yet.**

## Development Environments
Sometimes you may need to disable SSL security on your development systems. You can do it by calling the `verify` method
with the `false` parameter. Note: This is not recommended on production systems.

```php
use Maicol07\OpenIDConnect\Client;

$oidc = (new Client())
    ->providerUrl('https://id.example.com')
    ->clientId('ClientIDHere')
    ->clientSecret('ClientSecretHere')
    ->verifySsl(false)
```

### Todo
- Dynamic registration does not support registration auth tokens and endpoints

  [1]: https://openid.net/specs/openid-connect-basic-1_0-15.html#id_res

## Contributing
 - All pull requests, once merged, should be added to the CHANGELOG.md file.
