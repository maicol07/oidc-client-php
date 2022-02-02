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

use cse\helpers\Session;
use Exception;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use JetBrains\PhpStorm\NoReturn;
use Maicol07\OpenIDConnect\ClientException;

trait Authorization
{
    private string $authorization_endpoint;
    private array $response_types;
    private array $pkce_algorithms = ['S256' => 'sha256', 'plain' => false];
    /** Allow OAuth 2 implicit flow; see http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth */
    private bool $allow_implicit_flow = false;
    private bool $authorization_response_iss_parameter_supported;

    /**
     * Start Here
     *
     * @throws ClientException
     * @throws Exception
     */
    #[NoReturn]
    private function requestAuthorization(): void
    {
        $auth_endpoint = $this->getAuthorizationUrl();

        session_write_close();
        $this->redirect($auth_endpoint);
    }

    /**
     * Get the authorization URL
     * @throws Exception
     */
    public function getAuthorizationUrl(?array $query_params = null, ?string $state = null): string
    {
        $auth_endpoint = $this->authorization_endpoint;

        // State essentially acts as a session key for OIDC
        $state = $state ?? Str::random();
        Session::set('oidc_state', $state);

        $params = collect([
            'response_type' => 'code',
            'redirect_uri' => $this->redirect_uri,
            'client_id' => $this->client_id,
            'state' => $state,
            'scope' => implode(' ', array_merge($this->scopes, ['openid']))
        ])->merge($query_params);

        if ($this->enable_nonce) {
            $nonce = Str::random();
            Session::set('oidc_nonce', $nonce);
            $params->put('nonce', $nonce);
        }

        // If the client has been registered with additional response types
        if (count($this->response_types) > 0) {
            $params->put('response_type', implode(' ', $this->response_types));
        }

        // If the OP supports Proof Key for Code Exchange (PKCE) and it is enabled
        // PKCE will only used in pure authorization code flow and hybrid flow
        if (
            $this->enable_pkce
            && !empty($this->code_challenge_method)
            && (empty($this->response_types) || count(array_diff($this->response_types, ['token', 'id_token'])) > 0)
        ) {
            // Generate a cryptographically secure code
            $code_verifier = bin2hex(random_bytes(64));
            Session::set('oidc_code_verifier', $code_verifier);
            $code_challenge = !empty($this->pkce_algorithms[$this->code_challenge_method])
                ? rtrim(
                    strtr(
                        base64_encode(
                            hash(
                                $this->pkce_algorithms[$this->code_challenge_method],
                                $code_verifier,
                                true
                            )
                        ),
                        '+/',
                        '-_'
                    ),
                    '='
                )
                : $code_verifier;
            $params->put('code_challenge', $code_challenge)->put('code_challenge_method', $this->code_challenge_method);
        }

        $auth_endpoint .= (!str_contains($auth_endpoint, '?') ? '?' : '&') . Arr::query($params->all());
        return $auth_endpoint;
    }
}
