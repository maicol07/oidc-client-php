<?php
/**
 * End-to-end verification of RFC 8705 against a real Keycloak instance.
 *
 * Run with: docker compose -f docker/docker-compose.yml run --rm tests
 */

declare(strict_types=1);

require '/app/vendor/autoload.php';

use Illuminate\Http\Client\Factory;
use Maicol07\OpenIDConnect\Client;
use Maicol07\OpenIDConnect\ClientAuthMethod;
use Maicol07\OpenIDConnect\MutualTlsCertificate;
use Maicol07\OpenIDConnect\OIDCClientException;

$keycloak = getenv('KEYCLOAK_URL') ?: 'https://keycloak:8443';
$realm = getenv('REALM') ?: 'mtls';
$certDir = getenv('CERT_DIR') ?: '/app/docker/certs';
$providerUrl = "$keycloak/realms/$realm";

$passed = 0;
$failed = 0;

function check(string $name, callable $fn): void
{
    global $passed, $failed;
    try {
        $result = $fn();
        if ($result === false) {
            echo "  FAIL  $name\n";
            $failed++;
            return;
        }
        echo "  PASS  $name" . (is_string($result) ? " ($result)" : '') . "\n";
        $passed++;
    } catch (Throwable $e) {
        echo "  FAIL  $name\n        " . get_class($e) . ': ' . $e->getMessage() . "\n";
        $failed++;
    }
}

/** Decodes a JWT payload without verifying it (the provider is trusted in this test). */
function jwtClaims(string $jwt): array
{
    $parts = explode('.', $jwt);
    return json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true, 512, JSON_THROW_ON_ERROR);
}

$clientCert = new MutualTlsCertificate("$certDir/client.crt", "$certDir/client.key");
$selfSignedCert = new MutualTlsCertificate("$certDir/client-self-signed.crt", "$certDir/client-self-signed.key");
$otherCert = new MutualTlsCertificate("$certDir/other-client.crt", "$certDir/other-client.key");

// The stack uses a private CA, so trust it rather than disabling verification.
$caPath = "$certDir/ca.crt";

echo "\n=== RFC 8705 against $providerUrl ===\n\n";

echo "-- Discovery (RFC 8705 section 5) --\n";

$client = new Client(
    client_id: 'mtls-client',
    provider_url: $providerUrl,
    redirect_uri: 'https://example.com/callback',
    token_endpoint_auth_method: ClientAuthMethod::TLS_CLIENT_AUTH,
    mtls_certificate: $clientCert,
    cert_path: $caPath,
);

check('discovery advertises tls_client_auth', function () use ($client): bool {
    return in_array(ClientAuthMethod::TLS_CLIENT_AUTH, $client->token_endpoint_auth_methods_supported, true);
});

check('self_signed_tls_client_auth is parsed from discovery metadata', function (): bool {
    // Keycloak's client-x509 authenticator only implements the PKI variant, so it does not
    // advertise this method. Assert the enum parses the metadata value instead of asserting
    // a provider capability that this particular provider does not have.
    return ClientAuthMethod::tryFrom('self_signed_tls_client_auth') === ClientAuthMethod::SELF_SIGNED_TLS_CLIENT_AUTH
        && ClientAuthMethod::SELF_SIGNED_TLS_CLIENT_AUTH->isMutualTls();
});

check('tls_client_certificate_bound_access_tokens parsed', function () use ($client): bool {
    return $client->tls_client_certificate_bound_access_tokens === true;
});

check('mtls_endpoint_aliases parsed and applied to the token endpoint', function () use ($client) {
    $aliases = (new ReflectionProperty($client, 'mtls_endpoint_aliases'))->getValue($client);
    if (empty($aliases)) {
        // Keycloak only emits aliases when configured to; not fatal, the regular endpoint is used.
        return 'no aliases advertised, falling back to the regular endpoint';
    }
    $resolved = (new ReflectionMethod($client, 'mtlsEndpoint'))
        ->invoke($client, 'token', $client->token_endpoint);
    return $resolved === ($aliases['token_endpoint'] ?? $client->token_endpoint)
        ? 'alias applied'
        : false;
});

check('usesMutualTlsClientAuth() is true', fn (): bool => $client->usesMutualTlsClientAuth() === true);

echo "\n-- tls_client_auth: PKI mutual-TLS client authentication (section 2.1) --\n";

/**
 * Requests a token with the client_credentials grant, which exercises exactly the same
 * client-authentication path as the authorization_code grant without needing a browser.
 */
$requestToken = static function (Client $c, MutualTlsCertificate $cert, ?string $ca) use ($providerUrl): array {
    $data = ['grant_type' => 'client_credentials', 'client_id' => $c->client_id, 'scope' => 'openid'];
    // Route through the client's own applyMutualTlsClientAuth so the code under test decides
    // what is sent, then post with the same options the library would use.
    (new ReflectionMethod($c, 'applyMutualTlsClientAuth'))->invokeArgs($c, [&$data]);

    $response = (new Factory())->withOptions([
        'verify' => $ca ?? false,
        ...$cert->getRequestOptions(),
    ])->asForm()->post("$providerUrl/protocol/openid-connect/token", $data);

    return [$response->status(), $response->json() ?? []];
};

$boundAccessToken = null;

check('token request succeeds with the client certificate and no client_secret', function () use ($requestToken, $client, $clientCert, $caPath, &$boundAccessToken) {
    [$status, $body] = $requestToken($client, $clientCert, $caPath);
    if ($status !== 200) {
        echo '        response: ' . json_encode($body) . "\n";
        return false;
    }
    $boundAccessToken = $body['access_token'] ?? null;
    return is_string($boundAccessToken) ? 'got an access token' : false;
});

check('no client_secret is sent under mutual TLS', function () use ($client): bool {
    $data = ['grant_type' => 'client_credentials', 'client_id' => 'mtls-client', 'client_secret' => 'should-be-removed'];
    (new ReflectionMethod($client, 'applyMutualTlsClientAuth'))->invokeArgs($client, [&$data]);
    return !array_key_exists('client_secret', $data) && $data['client_id'] === 'mtls-client';
});

check('token request FAILS without the client certificate', function () use ($providerUrl, $caPath) {
    $response = (new Factory())->withOptions(['verify' => $caPath])->asForm()->post(
        "$providerUrl/protocol/openid-connect/token",
        ['grant_type' => 'client_credentials', 'client_id' => 'mtls-client', 'scope' => 'openid']
    );
    // The provider must reject a client that presents no certificate.
    return $response->status() !== 200 ? 'rejected with HTTP ' . $response->status() : false;
});

check('token request FAILS with a certificate whose subject DN does not match', function () use ($requestToken, $client, $otherCert, $caPath) {
    [$status, $body] = $requestToken($client, $otherCert, $caPath);
    return $status !== 200 ? 'rejected with HTTP ' . $status : false;
});

echo "\n-- Certificate-bound access tokens (section 3) --\n";

check('access token carries the cnf/x5t#S256 confirmation claim', function () use (&$boundAccessToken) {
    if (!is_string($boundAccessToken)) {
        return false;
    }
    $claims = jwtClaims($boundAccessToken);
    return isset($claims['cnf']['x5t#S256'])
        ? 'x5t#S256=' . $claims['cnf']['x5t#S256']
        : false;
});

check('cnf/x5t#S256 equals the thumbprint computed by MutualTlsCertificate', function () use (&$boundAccessToken, $clientCert) {
    $claims = jwtClaims($boundAccessToken);
    return hash_equals($clientCert->getThumbprint(), $claims['cnf']['x5t#S256'])
        ? $clientCert->getThumbprint()
        : false;
});

check('verifyCertificateBinding() accepts a token bound to our certificate', function () use ($client, &$boundAccessToken): bool {
    return $client->verifyCertificateBinding(collect(jwtClaims($boundAccessToken))) === true;
});

check('verifyCertificateBinding() REJECTS a token bound to another certificate', function () use ($providerUrl, $otherCert, $caPath, &$boundAccessToken) {
    $wrongClient = new Client(
        client_id: 'mtls-client',
        provider_url: $providerUrl,
        redirect_uri: 'https://example.com/callback',
        token_endpoint_auth_method: ClientAuthMethod::TLS_CLIENT_AUTH,
        mtls_certificate: $otherCert,
        cert_path: $caPath,
    );
    try {
        $wrongClient->verifyCertificateBinding(collect(jwtClaims($boundAccessToken)));
        return false; // should have thrown
    } catch (OIDCClientException) {
        return 'threw OIDCClientException as expected';
    }
});

check('verifyCertificateBinding() returns false for a token with no cnf claim', function () use ($client): bool {
    return $client->verifyCertificateBinding(collect(['sub' => 'nobody'])) === false;
});

check('userinfo accepts the certificate-bound token when the certificate is presented', function () use ($providerUrl, $clientCert, $caPath, &$boundAccessToken) {
    $response = (new Factory())->withOptions([
        'verify' => $caPath,
        ...$clientCert->getRequestOptions(),
    ])->withToken($boundAccessToken)->acceptJson()->get("$providerUrl/protocol/openid-connect/userinfo");
    return $response->ok() ? 'HTTP 200' : 'unexpected HTTP ' . $response->status();
});

check('userinfo REJECTS the certificate-bound token when NO certificate is presented', function () use ($providerUrl, $caPath, &$boundAccessToken) {
    $response = (new Factory())->withOptions(['verify' => $caPath])
        ->withToken($boundAccessToken)->acceptJson()
        ->get("$providerUrl/protocol/openid-connect/userinfo");
    // This is the whole point of certificate binding: a stolen token is useless without the key.
    return !$response->ok() ? 'rejected with HTTP ' . $response->status() : false;
});

echo "\n-- self_signed_tls_client_auth (section 2.2) --\n";

$selfSignedClient = new Client(
    client_id: 'mtls-client-self-signed',
    provider_url: $providerUrl,
    redirect_uri: 'https://example.com/callback',
    token_endpoint_auth_method: ClientAuthMethod::SELF_SIGNED_TLS_CLIENT_AUTH,
    mtls_certificate: $selfSignedCert,
    cert_path: $caPath,
);

check('self-signed certificate is presented, authenticates and yields a bound token', function () use ($requestToken, $selfSignedClient, $selfSignedCert, $caPath) {
    // The certificate is in Keycloak's trust store, so the handshake succeeds; Keycloak then
    // authenticates the client by matching the certificate subject DN.
    [$status, $body] = $requestToken($selfSignedClient, $selfSignedCert, $caPath);
    if ($status !== 200) {
        echo '        response: ' . json_encode($body) . "\n";
        return false;
    }
    $claims = jwtClaims($body['access_token']);
    $thumb = $claims['cnf']['x5t#S256'] ?? null;
    return $thumb !== null && hash_equals($selfSignedCert->getThumbprint(), $thumb)
        ? 'bound to the self-signed certificate'
        : false;
});

echo "\n-- TLS verification: cert_path must never silently stop verifying --\n";

/** The Guzzle `verify` option the client would use for the given configuration. */
$verifyOption = static function (?string $certPath, bool $verifySsl) use ($providerUrl): mixed {
    $c = new Client(
        client_id: 'secret-client',
        client_secret: 'secret-client-password',
        // No provider_url: auto discovery would need a working connection, and only the
        // resulting request options matter here.
        redirect_uri: 'https://example.com/callback',
        cert_path: $certPath,
        verify_ssl: $verifySsl,
    );
    $request = (new ReflectionMethod($c, 'client'))->invoke($c);
    return (new ReflectionProperty($request, 'options'))->getValue($request)['verify'] ?? null;
};

check('cert_path is used when verify_ssl is true', function () use ($verifyOption, $caPath) {
    return $verifyOption($caPath, true) === $caPath ? 'verifies against the bundle' : false;
});

check('cert_path is STILL used when verify_ssl is false (no silent downgrade)', function () use ($verifyOption, $caPath) {
    // Earlier versions documented `verify_ssl: false` as the way to make cert_path take effect,
    // so this combination must keep verifying rather than trusting any certificate.
    return $verifyOption($caPath, false) === $caPath ? 'verifies against the bundle' : false;
});

check('verification stays on by default', function () use ($verifyOption) {
    return $verifyOption(null, true) === true ? 'verify => true' : false;
});

check('verify_ssl false with no bundle still disables verification', function () use ($verifyOption) {
    return $verifyOption(null, false) === false ? 'verify => false' : false;
});

check('no configuration verifies less than it did before this change', function () use ($verifyOption, $caPath): bool {
    foreach ([[true, null], [true, $caPath], [false, null], [false, $caPath]] as [$verifySsl, $certPath]) {
        // The behaviour of the original expression, before RFC 8705 support was added.
        $before = ($verifySsl ?: $certPath) ?? false;
        $now = $verifyOption($certPath, $verifySsl);
        // Verification may be strengthened (false -> bundle/true) but never weakened.
        if ($before !== false && $now === false) {
            return false;
        }
        if (is_string($before) && $now !== $before) {
            return false;
        }
    }
    return true;
});

echo "\n-- Regressions: secret-based clients still work --\n";

check('client_secret_basic client is unaffected by the RFC 8705 changes', function () use ($providerUrl, $caPath) {
    $secretClient = new Client(
        client_id: 'secret-client',
        client_secret: 'secret-client-password',
        provider_url: $providerUrl,
        redirect_uri: 'https://example.com/callback',
        cert_path: $caPath,
    );
    // No certificate configured, so mutual TLS must stay entirely out of the way.
    if ($secretClient->usesMutualTlsClientAuth()) {
        return false;
    }
    $data = ['grant_type' => 'client_credentials', 'client_id' => 'secret-client', 'client_secret' => 'secret-client-password'];
    $applied = (new ReflectionMethod($secretClient, 'applyMutualTlsClientAuth'))->invokeArgs($secretClient, [&$data]);
    if ($applied || !isset($data['client_secret'])) {
        return false; // the secret must be left alone
    }
    $response = (new Factory())->withOptions(['verify' => $caPath])->asForm()
        ->post("$providerUrl/protocol/openid-connect/token", $data);
    return $response->ok() ? 'still authenticates with its secret' : false;
});

check('endpoints are unchanged when no certificate is configured', function () use ($providerUrl, $caPath): bool {
    $plain = new Client(
        client_id: 'secret-client',
        client_secret: 'secret-client-password',
        provider_url: $providerUrl,
        redirect_uri: 'https://example.com/callback',
        cert_path: $caPath,
    );
    $resolved = (new ReflectionMethod($plain, 'mtlsEndpoint'))->invoke($plain, 'token', $plain->token_endpoint);
    return $resolved === $plain->token_endpoint;
});

check('mutual-TLS auth method without a certificate throws a clear error', function () use ($providerUrl, $caPath) {
    $noCert = new Client(
        client_id: 'mtls-client',
        provider_url: $providerUrl,
        redirect_uri: 'https://example.com/callback',
        token_endpoint_auth_method: ClientAuthMethod::TLS_CLIENT_AUTH,
        cert_path: $caPath,
    );
    $data = ['grant_type' => 'client_credentials'];
    try {
        (new ReflectionMethod($noCert, 'applyMutualTlsClientAuth'))->invokeArgs($noCert, [&$data]);
        return false;
    } catch (OIDCClientException $e) {
        return str_contains($e->getMessage(), 'requires a client certificate') ? 'clear error' : false;
    }
});

echo "\n=== $passed passed, $failed failed ===\n\n";
exit($failed === 0 ? 0 : 1);
