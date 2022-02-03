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

/** @noinspection PhpUnused */
/** @noinspection PhpPropertyOnlyWrittenInspection */

namespace Maicol07\OpenIDConnect;

use Exception;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use JetBrains\PhpStorm\NoReturn;
use Maicol07\OpenIDConnect\Traits\Authorization;
use Maicol07\OpenIDConnect\Traits\AutoDiscovery;
use Maicol07\OpenIDConnect\Traits\DynamicRegistration;
use Maicol07\OpenIDConnect\Traits\ImplictFlow;
use Maicol07\OpenIDConnect\Traits\JWT;
use Maicol07\OpenIDConnect\Traits\Token;

/**
 *
 * Please note this class stores nonces by default in $_SESSION['openid_connect_nonce']
 *
 */
class Client
{
    use Authorization;
    use Token;
    use AutoDiscovery;
    use DynamicRegistration;

    use ImplictFlow;
    use JWT;

    private string $client_id;
    private string $client_secret;
    private ?string $issuer;
    private string $access_token;
    private string $id_token;
    private array $scopes;
    private string $redirect_uri;

    /**
     * @var string holds code challenge method for PKCE mode
     * @see https://tools.ietf.org/html/rfc7636
     */
    private string $code_challenge_method;
    private bool $enable_pkce;
    private bool $enable_nonce;

    private PendingRequest $http_client;

    // Endpoints
    private string $userinfo_endpoint;
    private ?string $end_session_endpoint;

    /**
     * @param array {
     *     client_id: string,
     *     client_secret: string,
     *     provider_url?: string,
     *     issuer?: string,
     *     http_proxy?: string,
     *     cert_path?: string,
     *     verify?: bool,
     *     scopes?: array<string>,
     *     enable_pkce?: bool,
     *     enable_nonce?: bool,
     *     allow_implicit_flow?: bool,
     *     code_challenge_method?: string,
     *     timeout?: int,
     *     leeway?: int,
     *     redirect_uri?: int,
     *     response_types?: array<string>,
     *     authorization_endpoint?: string,
     *     authorization_response_iss_parameter_supported?: bool,
     *     token_endpoint?: string,
     *     token_endpoint_auth_methods_supported?: array<string>,
     *     userinfo_endpoint?: string,
     *     end_session_endpoint?: string,
     *     registration_endpoint?: string,
     *     introspect_endpoint?: string,
     *     revocation_endpoint?: string,
     *     jwt_signing_method?: 'sha256'|'sha384'|'sha512',
     *     jwt_key?: string,
     *     jwt_signing_key?: string,
     *     jwt_plain_key?: bool
     * } $user_config Config for the OIDC Client.
     * The missing config values will be retrieved from the provider via auto-discovery if the `provider_url` exists
     * and the auto-discovery endpoint is supported.
     *
     */
    public function __construct(array $user_config)
    {
        $user_config = array_filter($user_config, static fn ($value) => !is_null($value));

        $this->http_client = (new Factory())->withOptions([
            'connect_timeout' => Arr::get($user_config, 'timeout', 0),
            'proxy' => Arr::get($user_config, 'http_proxy'),
            'verify' => Arr::get($user_config, 'verify', true) ?: Arr::get($user_config, 'cert_path', false)
        ]);

        $provider_url = rtrim(Arr::get($user_config, 'provider_url'), '/');
        $query_params = Arr::get($user_config, 'well_known_request_params');

        $config = $this->autoDiscovery($provider_url, $query_params)?->merge($user_config) ?? collect($user_config);

        $provider_url = $this->trimDiscoveryPath($provider_url);

        $props = [
            'client_id' => null,
            'client_secret' => null,
            'issuer' => $provider_url,
            'scopes' => [],
            'enable_pkce' => true,
            'enable_nonce' => true,
            'allow_implicit_flow' => false,
            'code_challenge_method' => 'plain',
            'leeway' => 300,
            'redirect_uri' => $this->getCurrentURL(),
            'response_types' => [],
            'authorization_endpoint' => null,
            'authorization_response_iss_parameter_supported' => false,
            'token_endpoint' => null,
            'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
            'userinfo_endpoint' => null,
            'end_session_endpoint' => null,
            'registration_endpoint' => null,
            'introspect_endpoint' => null,
            'revocation_endpoint' => null,
            'jwt_signing_method' => 'HS256',
            'jwt_key' => Arr::get($config, 'client_secret'),
            'jwt_signing_key' => null,
            'jwt_plain_key' => false
        ];
        foreach ($props as $prop => $default) {
            $this->{$prop} = $config->get($prop, $default);
        }

        if (empty($this->code_challenge_method)) {
            $methods = $config->get('code_challenge_methods_supported', []);
            if (in_array('S256', $methods, true)) {
                $this->code_challenge_method = 'S256';
            } else {
                $this->code_challenge_method = 'plain';
            }
        }
    }

    /**
     * Authenticate the user
     *
     * @throws ClientException
     * @throws Exception
     */
    public function authenticate(): bool
    {
        $request = Request::capture();

        $this->validateCallback($request);

        // If we have an authorization code then proceed to request a token
        $code = $request->get('code');
        if ($code) {
            return $this->token($request, $code);
        }

        $id_token = $request->get('id_token');
        if ($this->allow_implicit_flow && $id_token) {
            $this->implictFlow($request, $id_token);
        }

        $this->requestAuthorization();
    }

    private function validateCallback(Request $request): void
    {
        // protect against mix-up attacks
        // experimental feature, see https://tools.ietf.org/html/draft-ietf-oauth-iss-auth-resp-00
        if ($this->authorization_response_iss_parameter_supported && $request->hasAny(['error', 'code', 'id_token'])
            && $request->get('iss') === $this->issuer
        ) {
            throw new ClientException('Error: validation of iss response parameter failed');
        }

        // Do a preemptive check to see if the provider has thrown an error from a previous redirect.
        if ($request->has('error')) {
            $description = ' Description: ' . $request->get('error_description', 'No description provided');
            throw new ClientException('Error: ' . $request->get('error') . $description);
        }
    }

    /**
     * It calls the end-session endpoint of the OpenID Connect provider to notify the OpenID
     * Connect provider that the end-user has logged out of the relying party site
     * (the client application).
     *
     * @param string $id_token ID token (obtained at login)
     * @param string|null $redirect URL to which the RP is requesting that the End-User's User Agent
     * be redirected after a logout has been performed. The value MUST have been previously
     * registered with the OP. Value can be null.
     *
     */
    #[NoReturn]
    public function signOut(string $id_token, ?string $redirect = null): void
    {
        $endpoint = $this->end_session_endpoint;

        if ($redirect === null) {
            $params = ['id_token_hint' => $id_token];
        } else {
            $params = [
                'id_token_hint' => $id_token,
                'post_logout_redirect_uri' => $redirect
            ];
        }

        $endpoint .= (!str_contains($endpoint, '?') ? '?' : '&') . Arr::query($params);
        $this->redirect($endpoint);
    }

    /**
     * Returns the user info
     *
     * @throws ClientException
     */
    public function getUserInfo(): UserInfo
    {
        $response = $this->http_client->withToken($this->access_token)
            ->acceptJson()
            ->get($this->userinfo_endpoint, ['schema' => 'openid']);

        if (!$response->ok()) {
            throw new ClientException(
                'The communication to retrieve user data has failed with status code ' . $response->body()
            );
        }

        return new UserInfo($response->collect()->put('id_token', $this->id_token));
    }

    #[NoReturn]
    public function redirect(string $url): void
    {
        header('Location: ' . $url);
        exit;
    }

    /** @noinspection GlobalVariableUsageInspection */
    public function getCurrentURL(): string
    {
        $protocol = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] === 443)
            ? "https://"
            : "http://";
        return $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    }

    public function getClientCredentials(): array
    {
        return [$this->client_id, $this->client_secret];
    }
}
