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
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use JetBrains\PhpStorm\ArrayShape;
use JetBrains\PhpStorm\NoReturn;
use Maicol07\OpenIDConnect\Traits\Authorization;
use Maicol07\OpenIDConnect\Traits\AutoDiscovery;
use Maicol07\OpenIDConnect\Traits\DynamicRegistration;
use Maicol07\OpenIDConnect\Traits\ImplictFlow;
use Maicol07\OpenIDConnect\Traits\JWT;
use Maicol07\OpenIDConnect\Traits\Token;

/**
 * @method $this clientId(string $client_id)
 * @method $this clientSecret(string $client_secret)
 * @method $this providerUrl(string $provider_url)
 * @method $this issuer(string $issuer)
 * @method $this scopes(string|Scope ...$scopes)
 * @method $this redirectUri(string $redirect_uri)
 * @method $this enablePkce(bool $enable_pkce)
 * @method $this enableNonce(bool $enable_nonce)
 * @method $this allowImplicitFlow(bool $allow_implcit_flow)
 * @method $this codeChallengeMethod(CodeChallengeMethod $code_challenge_method)
 * @method $this leeway(int $leeway)
 * @method $this responseType(ResponseType ...$response_type)
 * @method $this jwtSigningAlgorithm(JwtSigningAlgorithm $jwt_signing_algorithm)
 * @method $this jwtSigningKey(string $jwt_signing_key)
 * @method $this jwk(array $jwk)
 *
 * @method $this httpProxy(string $proxy)
 * @method $this certPath(string $cert_path)
 * @method $this verifySsl(bool $verify_ssl)
 * @method $this timeout(int $timeout)
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
    private ?string $provider_url = null;
    private ?string $issuer = null;
    /** @var array<string|Scope> */
    private array $scopes = [Scope::OPENID];
    private string $redirect_uri;
    private bool $enable_pkce = true;
    private bool $enable_nonce = true;
    /**
     * Holds code challenge method for PKCE mode
     * @see https://tools.ietf.org/html/rfc7636
     */
    private CodeChallengeMethod $code_challenge_method = CodeChallengeMethod::PLAIN;

    private ?string $http_proxy = null;
    private ?string $cert_path = null;
    private bool $verify_ssl = true;
    private int $timeout = 0;


    private string $access_token;
    private string $id_token;
    // Endpoints
    private string $userinfo_endpoint;
    private ?string $end_session_endpoint;

    public function __construct()
    {
        $this->redirectUri(Request::capture()->url());
    }

    public function __call(string $name, array $arguments): self
    {
        $property = Str::snake($name);
        if (property_exists($this, $property) && $arguments > 0) {
            $value = $arguments[0];
            $value = match ($property) {
                'provider_url' => $this->trimDiscoveryPath(rtrim($value, '/')),
                'scopes', 'response_types' => [...$arguments],
                default => $value
            };

            if ($property === 'provider_url') {
                $this->issuer($value);
            }

            $this->{$property} = $value;
        }
        return $this;
    }

    public function endpoints(
        ?string $authorization = null,
        ?string $token = null,
        ?string $userinfo = null,
        ?string $end_session = null,
        ?string $registration = null,
        ?string $introspect = null,
        ?string $revocation = null,
        ?string $jwks = null,
        #[ArrayShape([
            'authorization_response_iss_parameter_supported' => 'bool',
            'token_endpoint_auth_methods_supported' => 'Maicol07\OpenIDConnect\ClientAuthMethod[]',
        ])] array $options = []
    ): self {
        $this->authorization_endpoint = $authorization;
        $this->token_endpoint = $token;
        $this->userinfo_endpoint = $userinfo;
        $this->end_session_endpoint = $end_session;
        $this->registration_endpoint = $registration;
        $this->introspect_endpoint = $introspect;
        $this->revocation_endpoint = $revocation;
        $this->jwk_endpoint = $jwks;

        $this->authorization_response_iss_parameter_supported = $options['authorization_response_iss_parameter_supported'] ?? false;
        $this->token_endpoint_auth_methods_supported = $options['token_endpoint_auth_methods_supported'] ?? [];
        return $this;
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
     * Request RFC8693 Token Exchange
     * https://datatracker.ietf.org/doc/html/rfc8693
     */
    public function requestTokenExchange(string $subjectToken, string $subjectTokenType, string $audience = ''): Collection
    {
        $grant_type = 'urn:ietf:params:oauth:grant-type:token-exchange';

        $data = [
            'grant_type' => $grant_type,
            'subject_token_type' => $subjectTokenType,
            'subject_token' => $subjectToken,
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'scope' => $this->getScopeString()
        ];

        $client = $this->client();

        if (!empty($audience)) {
            $data['audience'] = $audience;
        }

        # Consider Basic authentication if provider config is set this way
        if (in_array(ClientAuthMethod::CLIENT_SECRET_BASIC, $this->token_endpoint_auth_methods_supported, true)) {
            $client = $client->withBasicAuth($this->client_id, $this->client_secret);
            unset($data['client_secret'], $data['client_id']);
        }

        return $client->post($this->token_endpoint, $data)->collect();
    }

    /**
     * Returns the user info
     *
     * @throws ClientException
     */
    public function getUserInfo(): UserInfo
    {
        $response = (new Factory())->withToken($this->access_token)
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

    public function getClientCredentials(): array
    {
        return [$this->client_id, $this->client_secret];
    }

    private function client(): PendingRequest
    {
        return (new Factory())
            ->withOptions([
                'connect_timeout' => $this->timeout,
                'proxy' => $this->http_proxy,
                'verify' => ($this->verify_ssl ?: $this->cert_path) ?? false
            ]);
    }

    /**
     * @param array<string|Scope> $additional_scopes
     * @return string
     */
    private function getScopeString(array $additional_scopes = []): string
    {
        $scopes = array_merge($this->scopes, $additional_scopes);
        return implode(' ', array_map(static fn (string|Scope $scope) => $scope instanceof Scope ? $scope->value : $scope, $scopes));
    }
}
