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

use cse\helpers\Session;
use Exception;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use JetBrains\PhpStorm\NoReturn;
use Maicol07\OpenIDConnect\OIDCClientException;
use Maicol07\OpenIDConnect\CodeChallengeMethod;
use Maicol07\OpenIDConnect\ResponseType;
use Maicol07\OpenIDConnect\Scope;

/**
 * This trait handles the authorization process.
 */
trait Authorization
{
    /**
     * Requests authorization from the OP. This will redirect the user to the OP's authorization endpoint.
     *
     * @throws OIDCClientException If the authorization endpoint is not set
     * @throws Exception If code_verifier cannot be generated due to random_bytes() failure
     */
    #[NoReturn]
    private function requestAuthorization(): void
    {
        $auth_endpoint = $this->getAuthorizationUrl();

        session_write_close();
        $this->redirect($auth_endpoint);
    }

    /**
     * Generates the authorization URL to redirect the user to.
     * @throws OIDCClientException If the authorization endpoint is not set
     * @throws Exception If code_verifier cannot be generated due to random_bytes() failure
     */
    public function getAuthorizationUrl(?array $query_params = null, ?string $state = null): string
    {
        $auth_endpoint = $this->authorization_endpoint;
        if (empty($auth_endpoint)) {
            throw new OIDCClientException('Authorization endpoint not set');
        }

        // State essentially acts as a session key for OIDC
        $state = $state ?? Str::random();
        Session::set('oidc_state', $state);

        $response_types = collect(in_array(ResponseType::CODE, $this->response_types, true) ? $this->response_types : [ResponseType::CODE]);
        if (!$this->allow_implicit_flow) {
            $response_types = $response_types->reject(static fn (ResponseType $type) => $type === ResponseType::ID_TOKEN || $type === ResponseType::TOKEN);
        }

        $params = collect([
            'response_type' => $response_types->map(static fn (ResponseType $type) => $type->value)->implode(' '),
            'client_id' => $this->client_id,
            'state' => $state,
            'scope' => $this->getScopeString([Scope::OPENID])
        ])->merge($query_params);

        if ($this->enable_nonce) {
            $nonce = Str::random();
            Session::set('oidc_nonce', $nonce);
            $params->put('nonce', $nonce);
        }

        // If the OP supports Proof Key for Code Exchange (PKCE) and it is enabled
        // PKCE will only used in pure authorization code flow and hybrid flow
        if (
            $this->enable_pkce
            && !empty($this->code_challenge_method)
            && (
                empty($this->response_types) || count(
                    array_diff(
                        array_map(static fn (ResponseType $type) => $type->value, $this->response_types),
                        [ResponseType::TOKEN->value, ResponseType::ID_TOKEN->value]
                    )) > 0
            )
        ) {
            // Generate a cryptographically secure code
            $code_verifier = bin2hex(random_bytes(64));
            Session::set('oidc_code_verifier', $code_verifier);
            $code_challenge = $this->code_challenge_method === CodeChallengeMethod::S256
                ? rtrim(strtr(base64_encode(hash($this->code_challenge_method->algorithm(), $code_verifier, true)), '+/', '-_'), '=')
                : $code_verifier;
            $params->put('code_challenge', $code_challenge)
                ->put('code_challenge_method', $this->code_challenge_method->value);
        }

        $auth_endpoint .= (!str_contains($auth_endpoint, '?') ? '?' : '&') . 'redirect_uri=' . $this->redirect_uri . '&' . Arr::query($params->all());
        return $auth_endpoint;
    }
}
