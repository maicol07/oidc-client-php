<?php
/*
 * Copyright © 2026 Maicol07 (https://maicol07.it)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may get a copy of the License at
 *
 *             http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

use Maicol07\OpenIDConnect\Client;
use Maicol07\OpenIDConnect\ClientAuthMethod;
use Maicol07\OpenIDConnect\MutualTlsCertificate;
use Maicol07\OpenIDConnect\OIDCClientException;

/*
 * RFC 8705 — Mutual-TLS Client Authentication and Certificate-Bound Access Tokens.
 *
 * These tests need no provider: certificates are generated on the fly and every assertion is
 * about what the client itself decides to send, present and accept. The handshake behaviour of
 * a real provider (a token request without a certificate being rejected, and so on) can only be
 * covered against a live mutual-TLS provider.
 */

test('certificate exposes the guzzle options that present it during the handshake', function () {
    $certificate = certificate('client');

    expect($certificate->getRequestOptions())->toBe([
        'cert' => $certificate->certificate_path,
        'ssl_key' => $certificate->private_key_path,
    ]);
});

test('certificate passphrase is carried into the guzzle options', function () {
    $certificate = new MutualTlsCertificate(
        certificate_path: certificate('client')->certificate_path,
        private_key_path: certificate('client')->private_key_path,
        passphrase: 'secret'
    );

    expect($certificate->getRequestOptions())->toBe([
        'cert' => [$certificate->certificate_path, 'secret'],
        'ssl_key' => [$certificate->private_key_path, 'secret'],
    ]);
});

test('certificate without a separate private key omits the ssl_key option', function () {
    $bundle = tempnam(sys_get_temp_dir(), 'oidc_bundle_');
    file_put_contents($bundle, file_get_contents(certificate('client')->certificate_path)
        . file_get_contents(certificate('client')->private_key_path));

    try {
        expect((new MutualTlsCertificate($bundle))->getRequestOptions())->toBe(['cert' => $bundle]);
    } finally {
        unlink($bundle);
    }
});

test('certificate thumbprint is the base64url encoded sha-256 of the der body', function () {
    $certificate = certificate('client');
    $pem = file_get_contents($certificate->certificate_path);
    preg_match('/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s', $pem, $matches);
    $expected = rtrim(strtr(base64_encode(hash('sha256', base64_decode(preg_replace('/\s+/', '', $matches[1])), true)), '+/', '-_'), '=');

    // Base64url: no padding and no '+' or '/' from standard base64.
    expect($certificate->getThumbprint())->toBe($expected)
        ->and($certificate->getThumbprint())->not->toContain('=')
        ->and($certificate->getThumbprint())->not->toContain('+')
        ->and($certificate->getThumbprint())->not->toContain('/');
});

test('certificate thumbprint ignores a private key bundled with the certificate', function () {
    $certificate = certificate('client');
    $bundle = tempnam(sys_get_temp_dir(), 'oidc_bundle_');
    file_put_contents($bundle, file_get_contents($certificate->certificate_path)
        . file_get_contents($certificate->private_key_path));

    try {
        expect((new MutualTlsCertificate($bundle))->getThumbprint())->toBe($certificate->getThumbprint());
    } finally {
        unlink($bundle);
    }
});

test('certificate thumbprints differ between certificates', function () {
    expect(certificate('client')->getThumbprint())->not->toBe(certificate('other')->getThumbprint());
});

test('unreadable certificate and private key are rejected on construction', function () {
    expect(fn () => new MutualTlsCertificate('/does/not/exist.crt'))
        ->toThrow(OIDCClientException::class, 'does not exist or is not readable');

    expect(fn () => new MutualTlsCertificate(certificate('client')->certificate_path, '/does/not/exist.key'))
        ->toThrow(OIDCClientException::class, 'does not exist or is not readable');
});

test('unparseable certificate is rejected when computing the thumbprint', function () {
    $garbage = tempnam(sys_get_temp_dir(), 'oidc_garbage_');
    file_put_contents($garbage, 'not a certificate');

    try {
        expect(fn () => (new MutualTlsCertificate($garbage))->getThumbprint())
            ->toThrow(OIDCClientException::class, 'Unable to parse the client certificate');
    } finally {
        unlink($garbage);
    }
});

test('mutual tls auth methods are recognised', function () {
    expect(ClientAuthMethod::tryFrom('tls_client_auth'))->toBe(ClientAuthMethod::TLS_CLIENT_AUTH)
        ->and(ClientAuthMethod::tryFrom('self_signed_tls_client_auth'))->toBe(ClientAuthMethod::SELF_SIGNED_TLS_CLIENT_AUTH)
        ->and(ClientAuthMethod::TLS_CLIENT_AUTH->isMutualTls())->toBeTrue()
        ->and(ClientAuthMethod::SELF_SIGNED_TLS_CLIENT_AUTH->isMutualTls())->toBeTrue()
        ->and(ClientAuthMethod::CLIENT_SECRET_BASIC->isMutualTls())->toBeFalse()
        ->and(ClientAuthMethod::PRIVATE_KEY_JWT->isMutualTls())->toBeFalse()
        ->and(ClientAuthMethod::NONE->isMutualTls())->toBeFalse();
});

test('client uses mutual tls when a certificate and a mutual tls method are configured', function () {
    expect(mtlsClient()->usesMutualTlsClientAuth())->toBeTrue();
});

test('client does not use mutual tls without a certificate', function () {
    $client = client(token_endpoint_auth_method: ClientAuthMethod::TLS_CLIENT_AUTH);

    expect($client->usesMutualTlsClientAuth())->toBeFalse();
});

test('client does not use mutual tls when the configured method is secret based', function () {
    $client = client(
        client_secret: 'a-secret',
        token_endpoint_auth_method: ClientAuthMethod::CLIENT_SECRET_BASIC,
        mtls_certificate: certificate('client')
    );

    expect($client->usesMutualTlsClientAuth())->toBeFalse();
});

test('an advertised mutual tls method is selected when a certificate is configured', function () {
    $client = client(mtls_certificate: certificate('client'));
    $this->setProperty($client, 'token_endpoint_auth_methods_supported', [
        ClientAuthMethod::CLIENT_SECRET_BASIC,
        ClientAuthMethod::TLS_CLIENT_AUTH,
    ]);

    expect($this->invokeMethod($client, 'getClientAuthMethod'))->toBe(ClientAuthMethod::TLS_CLIENT_AUTH)
        ->and($client->usesMutualTlsClientAuth())->toBeTrue();
});

test('an advertised mutual tls method is ignored when no certificate is configured', function () {
    // A provider advertising tls_client_auth must never push a secret based client onto a
    // method it cannot possibly use.
    $client = client(client_secret: 'a-secret');
    $this->setProperty($client, 'token_endpoint_auth_methods_supported', [ClientAuthMethod::TLS_CLIENT_AUTH]);

    expect($this->invokeMethod($client, 'getClientAuthMethod'))->toBeNull()
        ->and($client->usesMutualTlsClientAuth())->toBeFalse();
});

test('no client secret is sent under mutual tls', function () {
    $data = ['grant_type' => 'client_credentials', 'client_secret' => 'should-be-removed'];

    expect($this->invokeMethod(mtlsClient(), 'applyMutualTlsClientAuth', [&$data]))->toBeTrue()
        ->and($data)->not->toHaveKey('client_secret')
        ->and($data['client_id'] ?? null)->toBe('mtls-client');
});

test('a secret based client keeps its client secret', function () {
    $client = client(client_secret: 'a-secret', token_endpoint_auth_method: ClientAuthMethod::CLIENT_SECRET_POST);
    $data = ['grant_type' => 'client_credentials', 'client_secret' => 'a-secret'];

    expect($this->invokeMethod($client, 'applyMutualTlsClientAuth', [&$data]))->toBeFalse()
        ->and($data['client_secret'])->toBe('a-secret');
});

test('mutual tls auth method without a certificate throws a clear error', function () {
    $client = client(token_endpoint_auth_method: ClientAuthMethod::TLS_CLIENT_AUTH);
    $data = ['grant_type' => 'client_credentials'];

    expect(fn () => $this->invokeMethod($client, 'applyMutualTlsClientAuth', [&$data]))
        ->toThrow(OIDCClientException::class, 'requires a client certificate');
});

test('endpoints resolve to the mutual tls aliases advertised by the provider', function () {
    $client = mtlsClient();
    $this->setProperty($client, 'mtls_endpoint_aliases', [
        'token_endpoint' => 'https://mtls.example.com/token',
    ]);

    expect($this->invokeMethod($client, 'mtlsEndpoint', ['token', 'https://example.com/token']))
        ->toBe('https://mtls.example.com/token')
        // An endpoint without an alias keeps the regular URL.
        ->and($this->invokeMethod($client, 'mtlsEndpoint', ['userinfo', 'https://example.com/userinfo']))
        ->toBe('https://example.com/userinfo');
});

test('endpoints are unchanged when no certificate is configured', function () {
    $client = client(client_secret: 'a-secret');
    $this->setProperty($client, 'mtls_endpoint_aliases', ['token_endpoint' => 'https://mtls.example.com/token']);

    expect($this->invokeMethod($client, 'mtlsEndpoint', ['token', 'https://example.com/token']))
        ->toBe('https://example.com/token');
});

test('certificate bound access tokens alone route through the aliased endpoint', function () {
    // A client may authenticate with a secret and still ask for certificate-bound tokens: the
    // certificate has to be presented at the token endpoint, so the alias must be used.
    $client = client(
        client_secret: 'a-secret',
        token_endpoint_auth_method: ClientAuthMethod::CLIENT_SECRET_BASIC,
        mtls_certificate: certificate('client'),
        tls_client_certificate_bound_access_tokens: true
    );
    $this->setProperty($client, 'mtls_endpoint_aliases', ['token_endpoint' => 'https://mtls.example.com/token']);

    expect($this->invokeMethod($client, 'mtlsEndpoint', ['token', 'https://example.com/token']))
        ->toBe('https://mtls.example.com/token')
        // The certificate authenticates nothing here, it only binds the token.
        ->and($client->usesMutualTlsClientAuth())->toBeFalse();
});

test('a certificate used for neither authentication nor binding does not divert endpoints', function () {
    $client = client(
        client_secret: 'a-secret',
        token_endpoint_auth_method: ClientAuthMethod::CLIENT_SECRET_BASIC,
        mtls_certificate: certificate('client')
    );
    $this->setProperty($client, 'mtls_endpoint_aliases', ['token_endpoint' => 'https://mtls.example.com/token']);

    expect($this->invokeMethod($client, 'mtlsEndpoint', ['token', 'https://example.com/token']))
        ->toBe('https://example.com/token');
});

test('dynamic registration resolves the aliased registration endpoint', function () {
    // register() is where a mutual-TLS client announces itself, so it is the one call that most
    // needs the certificate presented.
    $client = mtlsClient();
    $this->setProperty($client, 'mtls_endpoint_aliases', [
        'registration_endpoint' => 'https://mtls.example.com/register',
    ]);

    expect($this->invokeMethod($client, 'mtlsEndpoint', ['registration', 'https://example.com/register']))
        ->toBe('https://mtls.example.com/register');
});

test('a token bound to the configured certificate is accepted', function () {
    $client = mtlsClient();

    expect($client->verifyCertificateBinding(collect(['cnf' => ['x5t#S256' => certificate('client')->getThumbprint()]])))
        ->toBeTrue();
});

test('a token bound to another certificate is rejected', function () {
    $client = mtlsClient();

    expect(fn () => $client->verifyCertificateBinding(collect(['cnf' => ['x5t#S256' => certificate('other')->getThumbprint()]])))
        ->toThrow(OIDCClientException::class, 'bound to a different certificate');
});

test('a token with no confirmation claim is not certificate bound', function () {
    expect(mtlsClient()->verifyCertificateBinding(collect(['sub' => 'nobody'])))->toBeFalse()
        ->and(mtlsClient()->verifyCertificateBinding(collect(['cnf' => ['x5t#S256' => '']])))->toBeFalse();
});

test('a certificate bound token is rejected when no certificate is configured', function () {
    $client = client(client_secret: 'a-secret');

    expect(fn () => $client->verifyCertificateBinding(collect(['cnf' => ['x5t#S256' => certificate('client')->getThumbprint()]])))
        ->toThrow(OIDCClientException::class, 'no client certificate is configured');
});

test('the client certificate is presented on every request', function () {
    $certificate = certificate('client');
    $options = requestOptions(mtlsClient());

    expect($options['cert'])->toBe($certificate->certificate_path)
        ->and($options['ssl_key'])->toBe($certificate->private_key_path);
});

test('no certificate options are set when no certificate is configured', function () {
    expect(requestOptions(client(client_secret: 'a-secret')))
        ->not->toHaveKey('cert')
        ->not->toHaveKey('ssl_key');
});

test('a ca bundle is always used to verify the provider, even when verify_ssl is false', function () {
    // Earlier versions documented `verify_ssl: false` as the way to make cert_path take effect,
    // so this combination must keep verifying rather than trusting any certificate.
    $bundle = certificate('client')->certificate_path;

    expect(requestOptions(client(cert_path: $bundle))['verify'])->toBe($bundle)
        ->and(requestOptions(client(cert_path: $bundle, verify_ssl: false))['verify'])->toBe($bundle);
});

test('verification stays on by default and is only disabled without a bundle', function () {
    expect(requestOptions(client())['verify'])->toBeTrue()
        ->and(requestOptions(client(verify_ssl: false))['verify'])->toBeFalse();
});

test('no configuration verifies less than it did before mutual tls support', function () {
    $bundle = certificate('client')->certificate_path;

    foreach ([[true, null], [true, $bundle], [false, null], [false, $bundle]] as [$verify_ssl, $cert_path]) {
        // The behaviour of the original expression, before RFC 8705 support was added.
        $before = ($verify_ssl ?: $cert_path) ?? false;
        $now = requestOptions(client(cert_path: $cert_path, verify_ssl: $verify_ssl))['verify'];

        // Verification may be strengthened (false -> bundle/true) but never weakened.
        if ($before !== false) {
            expect($now)->not->toBeFalse();
        }
        if (is_string($before)) {
            expect($now)->toBe($before);
        }
    }
});
