<?php
/*
 * Copyright © 2024 Maicol07 (https://maicol07.it)
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

use cse\helpers\Session;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use JsonException;
use Maicol07\OpenIDConnect\ClientAuthMethod;
use Maicol07\OpenIDConnect\OIDCClientException;
use SensitiveParameter;

trait Token
{
    private ?string $refresh_token;

    /**
     * Requests Access token with refresh token
     *
     * @param bool $send_scopes (optional) Controls whether scopes are sent in the request, defaults to true.
     * @throws ConnectionException
     */
    public function refreshToken(#[SensitiveParameter] string $refresh_token, bool $send_scopes = true): Collection
    {
        $data = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refresh_token,
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
        ];

        if ($send_scopes) {
            $data['scopes'] = $this->getScopeString();
        }

        $client = $this->client();

        // Consider Basic authentication if provider config is set this way
        if (in_array(ClientAuthMethod::CLIENT_SECRET_BASIC, $this->token_endpoint_auth_methods_supported, true)) {
            $client = $client->withBasicAuth($this->client_id, $this->client_secret);
            unset($data['client_secret'], $data['client_id']);
        }

        $response = $client->post($this->token_endpoint, $data)->collect();

        $this->access_token = $response->get('access_token');
        $this->refresh_token = $response->get('refresh_token');

        return $response;
    }

    /**
     * Introspect a given token — either access token or refresh token.
     *
     * @link https://tools.ietf.org/html/rfc7662
     * @noinspection SensitiveParameterInspection
     * @throws ConnectionException
     */
    public function introspectToken(
        #[SensitiveParameter] string $token,
        string $token_type_hint = '',
        ?string $client_id = null,
        #[SensitiveParameter] ?string $client_secret = null
    ): Collection {
        $data = compact('token');

        if ($token_type_hint) {
            $data['token_type_hint'] = $token_type_hint;
        }
        $client_id ??= $this->client_id;
        $client_secret ??= $this->client_secret;

        return $this->client()
            ->withBasicAuth($client_id, $client_secret)
            ->asForm()
            ->post($this->introspect_endpoint, $data)
            ->collect();
    }

    /**
     * Revoke a given token - either access token or refresh token.
     *
     * @see https://tools.ietf.org/html/rfc7009
     * @noinspection SensitiveParameterInspection
     * @throws ConnectionException
     */
    public function revokeToken(
        #[SensitiveParameter] string $token,
        string $token_type_hint = '',
        ?string $client_id = null,
        #[SensitiveParameter] ?string $client_secret = null
    ): Collection {
        $data = compact('token');

        if ($token_type_hint) {
            $data['token_type_hint'] = $token_type_hint;
        }
        $client_id ??= $this->client_id;
        $client_secret ??= $this->client_secret;

        return $this->client()
            ->withBasicAuth($client_id, $client_secret)
            ->acceptJson()
            ->post($this->revocation_endpoint, $data)
            ->collect();
    }

    /**
     * Request tokens from the token endpoint.
     *
     * @throws JsonException|ConnectionException
     * @noinspection SensitiveParameterInspection
     */
    private function token(Request $request, string $code): bool
    {
        $token_response = $this->requestTokens($code);

        // Throw an error if the server returns one
        $error = $token_response->get('error');
        if ($error) {
            $description = $token_response->get('error_description');
            throw new OIDCClientException($description ?: ('Got response: ' . $error));
        }

        // Do an OpenID Connect session check
        if ($request->get('state') !== Session::get('oidc_state')) {
            throw new OIDCClientException('Unable to determine state');
        }
        Session::remove('oidc_state');

        if (!$token_response->has('id_token')) {
            throw new OIDCClientException('User did not authorize openid scope.');
        }

        /** @noinspection UnusedFunctionResultInspection */
        $this->loadAndValidateJWT($token_response->get('id_token'));

        $this->id_token = $token_response->get('id_token');
        $this->access_token = $token_response->get('access_token');
        $this->refresh_token = $token_response->get('refresh_token');

        return true;
    }

    /**
     * Requests ID and Access tokens
     * @throws ConnectionException
     * @noinspection SensitiveParameterInspection
     */
    private function requestTokens(string $code): Collection
    {
        $data = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirect_uri,
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret
        ];

        // Consider Basic authentication if provider config is set this way
        $client = $this->client();
        if (in_array(ClientAuthMethod::CLIENT_SECRET_BASIC, $this->token_endpoint_auth_methods_supported, true)) {
            $client = $client->withBasicAuth($this->client_id, $this->client_secret);
            unset($data['client_secret'], $data['client_id']);
        }

        $code_verifier = Session::get('oidc_code_verifier');
        if ($this->enable_pkce && !empty($this->code_challenge_method) && !empty($code_verifier)) {
            $data['code_verifier'] = $code_verifier;
        }

        return $client->asForm()->post($this->token_endpoint, $data)->collect();
    }
}
