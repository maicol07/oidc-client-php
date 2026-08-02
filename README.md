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
- [RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://tools.ietf.org/html/rfc8705)
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
You should always use HTTPS for your application. If your provider uses a private CA or a self-signed certificate, set
`cert_path` to the CA bundle: the connection is then still fully verified, just against your own CA rather than the
system trust store. A bundle set this way is always used, so you do not need to touch `verify_ssl`.

You can also setup a proxy via the `http_proxy`.

```php
use Maicol07\OpenIDConnect\Client;

$oidc = new Client(
    provider_url: 'https://id.example.com',
    client_id: 'ClientIDHere',
    client_secret: 'ClientSecretHere',
    redirect_uri: 'https://example.com/callback.php',
    http_proxy: 'http://proxy.example.com:8080',
    cert_path: 'path/to/ca.pem'
);
```

Setting `verify_ssl: false` disables certificate verification entirely, which exposes tokens and the client secret to
anyone on the network path. Prefer `cert_path`, and see [Development Environments](#development-environments) if you
really need to turn verification off.

> **Note:** in earlier versions `cert_path` only took effect when `verify_ssl` was `false`. It is now honoured in both
> cases, so `cert_path: 'path/to/ca.pem', verify_ssl: false` keeps verifying against the bundle rather than silently
> trusting any certificate.

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

### Example 8: Mutual-TLS client authentication (RFC 8705)
Instead of a client secret, the client can authenticate with a certificate presented during the TLS
handshake. Pass the certificate through `mtls_certificate` and pick one of the two mutual-TLS methods:
`ClientAuthMethod::TLS_CLIENT_AUTH` (the certificate is issued by a CA the provider trusts) or
`ClientAuthMethod::SELF_SIGNED_TLS_CLIENT_AUTH` (the provider holds the certificate itself).

```php
use Maicol07\OpenIDConnect\Client;
use Maicol07\OpenIDConnect\ClientAuthMethod;
use Maicol07\OpenIDConnect\MutualTlsCertificate;

$oidc = new Client(
    provider_url: 'https://id.example.com',
    client_id: 'ClientIDHere',
    // No client_secret: the certificate authenticates the client
    redirect_uri: 'https://example.com/callback.php',
    token_endpoint_auth_method: ClientAuthMethod::TLS_CLIENT_AUTH,
    mtls_certificate: new MutualTlsCertificate(
        certificate_path: '/path/to/client.crt',
        private_key_path: '/path/to/client.key',
        // passphrase: 'private key passphrase, if it is encrypted'
    ),
);
$oidc->authenticate();
```

The certificate is presented on every request to the provider, and when the provider publishes
[`mtls_endpoint_aliases`](https://tools.ietf.org/html/rfc8705#section-5) those endpoints are used
automatically. If `token_endpoint_auth_method` is omitted, a mutual-TLS method announced by the
provider is selected only when a certificate is configured, so existing secret-based clients are
unaffected.

If the provider's certificate is issued by a private CA, point `cert_path` at the CA bundle so the
connection is still verified:

```php
$oidc = new Client(
    // ...
    cert_path: '/path/to/ca.crt',
);
```

### Example 9: Certificate-bound access tokens (RFC 8705 section 3)
A certificate-bound access token can only be used by the client holding the private key, so a stolen
token is useless on its own. Providers advertise this through
`tls_client_certificate_bound_access_tokens` in their discovery document, which is picked up
automatically; the token then carries a `cnf` claim with the `x5t#S256` thumbprint of the certificate.

`verifyCertificateBinding()` checks that such a token is bound to the configured certificate. It
returns `false` when the token is not bound at all and throws an `OIDCClientException` when it is
bound to a different certificate:

```php
use Maicol07\OpenIDConnect\OIDCClientException;

// Claims of an access token, or an introspection response
$claims = $oidc->introspectToken($access_token);

try {
    if ($oidc->verifyCertificateBinding($claims)) {
        // The token is bound to our certificate
    }
} catch (OIDCClientException $e) {
    // The token is bound to a different certificate — do not use it
}
```

Note that the authoritative check belongs to the resource server, which compares the thumbprint in
the token against the certificate presented to it.

## Development Environments

Sometimes you may need to disable SSL security on your development systems. You can do it by setting `verify_ssl` to
`false`. Note: This is not recommended on production systems.

If you only need to trust a private CA or a self-signed provider certificate, use `cert_path` instead (see
[Example 3](#example-3-network-and-security)): it keeps the connection verified. Note that `verify_ssl: false` only
disables verification when no `cert_path` is set — a bundle given there is always honoured.

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
2. Create a client named with the following settings:
   - Client ID: `oidc`
   - Client authentication: ON
   - Authorization: ON
   - Authentication Flow: Standard Flow, Implicit Flow (if you want to test implicit flow), Direct Access Grants
   - Client Secret: `oidc`
   - Valid Redirect URIs: `http://localhost:9999/callback`
   - Web Origins: `*`
3. Go to Credentials tab and copy the Secret
4. Tweak the PHPStorm Run configuration with your settings.

### Mutual TLS (RFC 8705)
The mutual-TLS support has a self-contained test stack that needs nothing but Docker. It generates a
CA and client certificates, starts a Keycloak configured for mutual TLS and certificate-bound access
tokens, and runs the tests against it:

```bash
./docker/run-tests.sh          # run the tests and tear the stack down
./docker/run-tests.sh --keep   # leave Keycloak running on https://localhost:8443 (admin/admin)
```

Besides the happy paths, the suite covers the cases that make the spec worth implementing: a token
request without a certificate is rejected, a certificate with the wrong subject DN is rejected, and a
certificate-bound access token is refused by the userinfo endpoint when the certificate is not
presented. Generated certificates stay out of git.

Two notes on Keycloak as a test provider: it implements the PKI variant (`tls_client_auth`) and does
not advertise `self_signed_tls_client_auth`, and its trust store must be a Java trust store built
with `keytool` — a PKCS#12 file created by `openssl pkcs12 -export -nokeys` makes it abort the TLS
handshake.

### Todo
- Dynamic registration does not support registration auth tokens and endpoints

## Contributing
- Issues and pull requests are welcome.

[1]: https://openid.net/specs/openid-connect-basic-1_0-15.html#id_res
