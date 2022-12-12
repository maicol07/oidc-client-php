<?php
/*
 * Copyright 2022 Maicol07 (https://maicol07.it)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Maicol07\OpenIDConnect\Traits;

use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Maicol07\OpenIDConnect\ClientAuthMethod;
use Maicol07\OpenIDConnect\CodeChallengeMethod;
use Maicol07\OpenIDConnect\JwtSigningAlgorithm;
use Maicol07\OpenIDConnect\ResponseType;
use Maicol07\OpenIDConnect\Scope;

trait AutoDiscovery
{
    private string $DISCOVERY_PATH = '.well-known/openid-configuration';

    public function autoDiscovery(string $provider_url, array|string|null $query_params = null): self
    {
        if ($provider_url) {
            $response = $this->client()
                ->get("$provider_url/$this->DISCOVERY_PATH", $query_params);

            if ($response->ok()) {
                $config = $response->collect();

                $response_types = [];
                $response_types_supported = $config->get('response_types_supported');
                if ($response_types_supported) {
                    $response_types = collect($response_types_supported)
                        ->map(fn (string $response_type) => explode(' ', $response_type))
                        ->reduce(function (array $carry, array $rt) use ($response_types) {
                            if (count($rt) > count($carry)) {
                                foreach ($rt as $response_type) {
                                    $carry[] = ResponseType::from($response_type);
                                }
                            }
                            return $carry;
                        }, []);
                }

                $this->issuer($config->get('issuer'))
                    ->endpoints(
                        $config->get('authorization_endpoint'),
                        $config->get('token_endpoint'),
                        $config->get('userinfo_endpoint'),
                        $config->get('end_sesion_endpoint'),
                        $config->get('registration_endpoint'),
                        $config->get('introspect_endpoint'),
                        $config->get('revocation_endpoint'),
                        $config->get('jwks_uri'),
                        options: [
                            'token_endpoint_auth_methods_supported' => array_map(
                                static fn (string $method) => ClientAuthMethod::from($method),
                                $config->get('token_endpoint_auth_methods_supported')
                            ),
                        ]
                    )
                    ->responseType(...$response_types)
                    ->scopes(...array_map(static fn (string $scope) => Scope::from($scope), $config->get('scopes_supported')))
                    ->jwtSigningMethod(JwtSigningAlgorithm::from($config->get('id_token_signing_alg_values_supported')[0]));

                if ($this->code_challenge_method === CodeChallengeMethod::PLAIN) {
                    $methods = $config->get('code_challenge_methods_supported', []);
                    if (in_array(CodeChallengeMethod::S256->value, $methods, true)) {
                        $this->code_challenge_method = CodeChallengeMethod::S256;
                    }
                }
            }
        }

        return $this;
    }

    private function trimDiscoveryPath(string $provider_url): string
    {
        return Str::endsWith($provider_url, $this->DISCOVERY_PATH)
            ? Str::replace($provider_url, $this->DISCOVERY_PATH, '')
            : $provider_url;
    }
}
