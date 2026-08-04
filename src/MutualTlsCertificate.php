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

namespace Maicol07\OpenIDConnect;

use SensitiveParameter;

/**
 * The client certificate (and its private key) presented during the TLS handshake
 * for mutual-TLS client authentication and certificate-bound access tokens.
 *
 * @see https://tools.ietf.org/html/rfc8705
 */
class MutualTlsCertificate
{
    /**
     * @param string $certificate_path Path to the PEM encoded client certificate
     * @param string|null $private_key_path Path to the PEM encoded private key. Can be null if the
     * key is bundled in the certificate file.
     * @param string|null $passphrase Passphrase of the private key (or of the certificate when the
     * key is bundled), if it is encrypted
     * @throws OIDCClientException If the certificate or the private key cannot be read
     * @noinspection SensitiveParameterInspection
     */
    public function __construct(
        public readonly string $certificate_path,
        public readonly ?string $private_key_path = null,
        #[SensitiveParameter] public readonly ?string $passphrase = null
    ) {
        if (!is_readable($this->certificate_path)) {
            throw new OIDCClientException(
                "The client certificate at \"{$this->certificate_path}\" does not exist or is not readable"
            );
        }

        if ($this->private_key_path !== null && !is_readable($this->private_key_path)) {
            throw new OIDCClientException(
                "The client private key at \"{$this->private_key_path}\" does not exist or is not readable"
            );
        }
    }

    /**
     * Guzzle request options that make the certificate be presented during the TLS handshake.
     *
     * @return array<string, string|array<int, string>>
     */
    public function getRequestOptions(): array
    {
        $options = [
            'cert' => $this->passphrase === null
                ? $this->certificate_path
                : [$this->certificate_path, $this->passphrase]
        ];

        if ($this->private_key_path !== null) {
            $options['ssl_key'] = $this->passphrase === null
                ? $this->private_key_path
                : [$this->private_key_path, $this->passphrase];
        }

        return $options;
    }

    /**
     * The certificate SHA-256 thumbprint, base64url encoded, as used in the `cnf` claim
     * `x5t#S256` confirmation method of a certificate-bound access token.
     *
     * @throws OIDCClientException If the certificate cannot be read or parsed
     * @see https://tools.ietf.org/html/rfc8705#section-3.1
     */
    public function getThumbprint(): string
    {
        $contents = file_get_contents($this->certificate_path);
        if ($contents === false) {
            throw new OIDCClientException(
                "Unable to read the client certificate at \"{$this->certificate_path}\""
            );
        }

        // The file may bundle the private key (and intermediates) alongside the certificate,
        // so hash the first certificate block only.
        $der = null;
        if (preg_match('/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s', $contents, $matches)) {
            $der = base64_decode((string) preg_replace('/\s+/', '', $matches[1]), true);
        }

        if (empty($der)) {
            throw new OIDCClientException(
                "Unable to parse the client certificate at \"{$this->certificate_path}\""
            );
        }

        return rtrim(strtr(base64_encode(hash('sha256', $der, true)), '+/', '-_'), '=');
    }
}
