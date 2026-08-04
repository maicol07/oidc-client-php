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

/** @noinspection PhpUnused */

namespace Maicol07\OpenIDConnect\Traits;

use Illuminate\Support\Collection;
use Maicol07\OpenIDConnect\ClientAuthMethod;
use Maicol07\OpenIDConnect\OIDCClientException;

/**
 * OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens.
 *
 * @see https://tools.ietf.org/html/rfc8705
 */
trait MutualTls
{
    /**
     * Endpoint aliases advertised by the provider for mutual-TLS clients.
     *
     * @var array<string, string>
     * @see https://tools.ietf.org/html/rfc8705#section-5
     */
    private array $mtls_endpoint_aliases = [];

    /**
     * Whether the client authenticates itself at the token endpoint through mutual TLS.
     *
     * @see https://tools.ietf.org/html/rfc8705#section-2
     */
    public function usesMutualTlsClientAuth(): bool
    {
        return $this->mtls_certificate !== null && $this->getClientAuthMethod()?->isMutualTls() === true;
    }

    /**
     * The mutual-TLS client authentication method to use, if any.
     *
     * An explicitly configured method always wins. Otherwise a mutual-TLS method announced by
     * the provider is only selected when a certificate is actually configured — a provider
     * advertising `tls_client_auth` must never push a client that has no certificate (a plain
     * client secret one, say) onto a method it cannot possibly use.
     */
    private function getClientAuthMethod(): ?ClientAuthMethod
    {
        if ($this->token_endpoint_auth_method instanceof ClientAuthMethod) {
            return $this->token_endpoint_auth_method;
        }

        if ($this->mtls_certificate === null) {
            return null;
        }

        // The supported methods are a public array, so a caller may well have passed method
        // names as strings rather than enum cases.
        return collect($this->token_endpoint_auth_methods_supported)
            ->map(static fn (mixed $method): ?ClientAuthMethod => $method instanceof ClientAuthMethod
                ? $method
                : (is_string($method) ? ClientAuthMethod::tryFrom($method) : null))
            ->first(static fn (?ClientAuthMethod $method): bool => $method?->isMutualTls() === true);
    }

    /**
     * Resolves an endpoint against the provider's mutual-TLS aliases.
     *
     * When the client authenticates with mutual TLS — or asks for certificate-bound tokens —
     * the aliased endpoint must be used instead of the regular one, as the aliases are
     * served on a host/port that requests a client certificate during the handshake.
     *
     * @param string $name The endpoint name without the `_endpoint` suffix, e.g. `token`
     * @param string|null $endpoint The regular endpoint URL
     * @see https://tools.ietf.org/html/rfc8705#section-5
     */
    private function mtlsEndpoint(string $name, ?string $endpoint): ?string
    {
        if (!$this->usesMutualTls()) {
            return $endpoint;
        }

        return $this->mtls_endpoint_aliases["{$name}_endpoint"] ?? $endpoint;
    }

    /**
     * Whether requests to the provider go through mutual TLS, either to authenticate the client
     * or to obtain certificate-bound access tokens.
     *
     * Both cases require the aliased endpoints: they are served on a host/port that requests a
     * client certificate during the handshake. Certificate-bound tokens are issued to the
     * certificate presented at the token endpoint, so they need it even when the client
     * authenticates with a secret - @see https://tools.ietf.org/html/rfc8705#section-3
     */
    private function usesMutualTls(): bool
    {
        return $this->usesMutualTlsClientAuth()
            || ($this->mtls_certificate !== null && $this->tls_client_certificate_bound_access_tokens);
    }

    /**
     * Applies mutual-TLS client authentication to a token endpoint request.
     *
     * With mutual TLS the client is authenticated by the certificate presented during the
     * handshake, so the client secret must not be sent; `client_id` is still required to
     * identify the client - @see https://tools.ietf.org/html/rfc8705#section-2
     *
     * @param array<string, mixed> $data The request body, modified in place
     * @throws OIDCClientException If mutual-TLS authentication is configured without a certificate
     */
    private function applyMutualTlsClientAuth(array &$data): bool
    {
        $method = $this->getClientAuthMethod();
        if ($method === null || !$method->isMutualTls()) {
            return false;
        }

        if ($this->mtls_certificate === null) {
            throw new OIDCClientException(
                "The \"{$method->value}\" client authentication method requires a client certificate. "
                . 'Pass one through the "mtls_certificate" parameter.'
            );
        }

        unset($data['client_secret']);
        $data['client_id'] = $this->client_id;

        return true;
    }

    /**
     * Verifies that an access token is bound to the client certificate presented to the provider.
     *
     * The `cnf` claim of a certificate-bound access token holds the SHA-256 thumbprint of the
     * certificate the token was issued to. This check is only possible when the access token is
     * a JWT the client can read, or when the introspection response carries the claim; a resource
     * server performs the authoritative check.
     *
     * @param Collection<string, mixed> $claims Claims of the access token, or an introspection response
     * @throws OIDCClientException If the token is bound to a different certificate
     * @see https://tools.ietf.org/html/rfc8705#section-3
     */
    public function verifyCertificateBinding(Collection $claims): bool
    {
        $thumbprint = data_get($claims->all(), 'cnf.x5t#S256');
        if (!is_string($thumbprint) || $thumbprint === '') {
            return false;
        }

        if ($this->mtls_certificate === null) {
            throw new OIDCClientException(
                'The token is certificate-bound but no client certificate is configured'
            );
        }

        if (!hash_equals($this->mtls_certificate->getThumbprint(), $thumbprint)) {
            throw new OIDCClientException(
                'The token is bound to a different certificate than the configured one'
            );
        }

        return true;
    }
}
