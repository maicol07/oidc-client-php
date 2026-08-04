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
use Maicol07\OpenIDConnect\Tests\TestCase;

/*
|--------------------------------------------------------------------------
| Test Case
|--------------------------------------------------------------------------
|
| The closure you provide to your test functions is always bound to a specific PHPUnit test
| case class. By default, that class is "PHPUnit\Framework\TestCase". Of course, you may
| need to change it using the "pest()" function to bind different classes or traits.
|
*/

pest()->extend(TestCase::class)->in('Feature');

/*
|--------------------------------------------------------------------------
| Expectations
|--------------------------------------------------------------------------
|
| When you're writing tests, you often need to check that values meet certain conditions. The
| "expect()" function gives you access to a set of "expectations" methods that you can use
| to assert different things. Of course, you may extend the Expectation API at any time.
|
*/

expect()->extend('toBeOne', function () {
    return $this->toBe(1);
});

/*
|--------------------------------------------------------------------------
| Functions
|--------------------------------------------------------------------------
|
| While Pest is very powerful out-of-the-box, you may have some testing code specific to your
| project that you don't want to repeat in every file. Here you can also expose helpers as
| global functions to help you to reduce the number of lines of code in your test files.
|
*/

/**
 * A self-signed certificate and its private key, generated once per test run and reused
 * across tests. Keeps the mutual-TLS tests free of both fixture files and a live provider.
 *
 * @param string $name Identifies the certificate; different names get different key pairs
 */
function certificate(string $name = 'client'): MutualTlsCertificate
{
    static $certificates = [];

    if (!isset($certificates[$name])) {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        if ($key === false) {
            throw new RuntimeException('Unable to generate a test key pair: ' . openssl_error_string());
        }

        $csr = openssl_csr_new(['commonName' => $name], $key, ['digest_alg' => 'sha256']);
        if ($csr === false) {
            throw new RuntimeException('Unable to generate a test CSR: ' . openssl_error_string());
        }

        $signed = openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256']);
        if ($signed === false) {
            throw new RuntimeException('Unable to sign the test certificate: ' . openssl_error_string());
        }

        openssl_x509_export($signed, $certificate);
        openssl_pkey_export($key, $private_key);

        $directory = sys_get_temp_dir() . '/oidc-client-php-tests';
        if (!is_dir($directory)) {
            mkdir($directory, 0700, true);
        }

        file_put_contents("$directory/$name.crt", $certificate);
        file_put_contents("$directory/$name.key", $private_key);
        chmod("$directory/$name.key", 0600);

        $certificates[$name] = new MutualTlsCertificate("$directory/$name.crt", "$directory/$name.key");
    }

    return $certificates[$name];
}

/**
 * A client that talks to no provider: without a provider_url the constructor skips auto
 * discovery, so only the configuration passed here decides how the client behaves.
 *
 * @param array<string, mixed> $parameters Constructor parameters to override
 */
function client(mixed ...$parameters): Client
{
    return new Client(...[
        'client_id' => 'mtls-client',
        'redirect_uri' => 'https://example.com/callback',
        ...$parameters,
    ]);
}

/** A client configured for PKI mutual-TLS client authentication (RFC 8705 section 2.1). */
function mtlsClient(): Client
{
    return client(
        token_endpoint_auth_method: ClientAuthMethod::TLS_CLIENT_AUTH,
        mtls_certificate: certificate('client')
    );
}

/**
 * The Guzzle request options the client would send, including the TLS `verify` setting and
 * any client certificate.
 *
 * @return array<string, mixed>
 */
function requestOptions(Client $client): array
{
    $request = (new ReflectionMethod($client, 'client'))->invoke($client);

    return (new ReflectionProperty($request, 'options'))->getValue($request);
}
