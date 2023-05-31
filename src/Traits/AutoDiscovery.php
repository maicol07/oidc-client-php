<?php
/*
 * Copyright © 2023 Maicol07 (https://maicol07.it)
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

namespace Maicol07\OpenIDConnect\Traits;

use Illuminate\Support\Str;
use Maicol07\OpenIDConnect\ClientAuthMethod;
use Maicol07\OpenIDConnect\CodeChallengeMethod;
use Maicol07\OpenIDConnect\JwtSigningAlgorithm;
use Maicol07\OpenIDConnect\ResponseType;

trait AutoDiscovery
{
    /** Path of the discovery document */
    private string $DISCOVERY_PATH = '.well-known/openid-configuration';

    /**
     * Auto discovery of the OpenID Connect provider
     *
     * @param string $provider_url The URL of the provider
     * @param array|string|null $query_params (optional) Query parameters to send with the request
     */
    public function autoDiscovery(string $provider_url, array|string|null $query_params = null): void
    {
        if ($provider_url) {
            $response = $this->client()
                ->get("$provider_url/$this->DISCOVERY_PATH", $query_params);

            if ($response->ok()) {
                $config = $response->collect();

                // Response types
                $response_types = [];
                $response_types_supported = $config->get('response_types_supported');
                if ($response_types_supported) {
                    $response_types = collect($response_types_supported)
                        ->map(static fn (string $response_type) => explode(' ', $response_type))
                        ->map(static fn (array $types) => array_map(static fn (string $type) => ResponseType::from($type), $types))
                        ->reject(static fn (array $response_type) => $response_type === [ResponseType::NONE])
                        ->reduce(static fn (array $carry, array $types) => count($types) > count($carry) ? $types : $carry, []);
                }
                $this->response_types = empty($this->response_types) ? $response_types : $this->response_types;
                $this->issuer ??= $config->get('issuer');

                // Endpoints
                foreach (['authorization', 'token', 'userinfo', 'end_session', 'registration', 'introspect', 'revocation'] as $key) {
                    $this->{"{$key}_endpoint"} ??= $config->get("{$key}_endpoint");
                }
                $this->jwks_endpoint ??= $config->get('jwks_uri');

                $this->token_endpoint_auth_methods_supported = empty($this->token_endpoint_auth_methods_supported) ? array_filter(array_map(
                    static fn (string $method) => ClientAuthMethod::tryFrom($method),
                    $config->get('token_endpoint_auth_methods_supported', [])
                )) : $this->token_endpoint_auth_methods_supported;

                $algorithms = $config->get('id_token_signing_alg_values_supported', []);
                $this->id_token_signing_alg_values_supported =
                    empty($this->id_token_signing_alg_values_supported)
                        ? array_filter(array_map(static fn (string $alg) => JwtSigningAlgorithm::tryFromName($alg), $algorithms))
                        : $this->id_token_signing_alg_values_supported;

                if ($this->code_challenge_method === CodeChallengeMethod::PLAIN) {
                    $methods = $config->get('code_challenge_methods_supported', []);
                    if (in_array(CodeChallengeMethod::S256->value, $methods, true)) {
                        $this->code_challenge_method = CodeChallengeMethod::S256;
                    }
                }

                $this->introspect_endpoint ??= $config->get('introspection_endpoint');
            }
        }
    }

    /**
     * Trim the discovery path from the provider url
     *
     * @param string $provider_url The provider url
     * @return string The provider url without the discovery path
     */
    private function trimDiscoveryPath(string $provider_url): string
    {
        if (Str::endsWith($provider_url, $this->DISCOVERY_PATH)) {
            return Str::replace($provider_url, $this->DISCOVERY_PATH, '');
        }
        return $provider_url;
    }
}
