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
/** @noinspection PhpPropertyOnlyWrittenInspection */

namespace Maicol07\OpenIDConnect;

use Exception;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use JetBrains\PhpStorm\NoReturn;
use Jose\Component\Core\JWKSet;
use Maicol07\OpenIDConnect\Traits\Authorization;
use Maicol07\OpenIDConnect\Traits\AutoDiscovery;
use Maicol07\OpenIDConnect\Traits\DynamicRegistration;
use Maicol07\OpenIDConnect\Traits\ImplicitFlow;
use Maicol07\OpenIDConnect\Traits\JWT;
use Maicol07\OpenIDConnect\Traits\Token;
use SensitiveParameter;

class Client
{
    use Authorization;
    use Token;
    use AutoDiscovery;
    use DynamicRegistration;
    use ImplicitFlow;
    use JWT;

    private string $access_token;
    private string $id_token;

    /**
     * @param string|null $client_id Client ID of the application registered on the OpenID Connect Provider (can be null if you use dynamic registration)
     * @param string|null $client_secret Client Secret of the application registered on the OpenID Connect Provider (can be null if you use dynamic registration)
     * @param string|null $provider_url URL of the OpenID Connect Provider
     * @param string|null $issuer Issuer of the OpenID Connect Provider (can be null if it matches the provider_url)
     * @param array<string|Scope> $scopes Scopes to request. Can be or an array of Scope enum values. Defaults to Scope::OPENID.
     * @param string|null $redirect_uri Redirect URI of the application registered on the OpenID Connect Provider (can be null if you use dynamic registration)
     * @param bool $enable_pkce Enable PKCE mode. Defaults to true - @see https://tools.ietf.org/html/rfc7636
     * @param bool $enable_nonce Enable nonce. Defaults to true - @see http://openid.net/specs/openid-connect-core-1_0.html#IDToken
     * @param CodeChallengeMethod $code_challenge_method Code challenge method for PKCE mode - @see https://tools.ietf.org/html/rfc7636
     * @param int $time_drift Time drift in seconds to allow when validating the id token. Defaults to 300.
     * @param ResponseType[] $response_types Response types to use in the authorization request. Defaults to ResponseType::CODE if nothing is set.
     * @param JwtSigningAlgorithm[] $id_token_signing_alg_values_supported Supported JWT signing algorithms (can be empty if you use auto discovery)
     * @param string|null $authorization_endpoint Authorization endpoint of the provider (can be null if you use auto discovery)
     * @param string|null $token_endpoint Token endpoint of the provider (can be null if you use auto discovery)
     * @param string|null $userinfo_endpoint Userinfo endpoint of the provider (can be null if you use auto discovery)
     * @param string|null $end_session_endpoint End session endpoint of the provider (can be null if you use auto discovery)
     * @param string|null $registration_endpoint Registration endpoint of the provider (can be null if you use auto discovery)
     * @param string|null $introspect_endpoint Introspect token endpoint of the provider (can be null if you use auto discovery)
     * @param string|null $revocation_endpoint Revocation endpoint of the provider (can be null if you use auto discovery)
     * @param string|null $jwks_endpoint JWKS endpoint of the provider (can be null if you use auto discovery)
     * @param bool $authorization_response_iss_parameter_supported Allow iss parameter in authorization response. Defaults to false - @see http://openid.net/specs/openid-connect-core-1_0.html#AuthResponseValidation
     * @param ClientAuthMethod[] $token_endpoint_auth_methods_supported Supported client authentication methods for token endpoint (can be empty if you use auto discovery)
     * @param string|null $http_proxy HTTP proxy to use for requests (can be null if you don't want to use a proxy)
     * @param string|null $cert_path Path to a custom certificate to use for requests (can be null if you don't want to use a custom certificate)
     * @param bool $verify_ssl Verify SSL certificates when making requests. Defaults to true.
     * @param int $timeout Timeout for requests. Defaults to 0.
     * @param string $client_name Name of the client for dynamic registration (can be null if you have already registered the client)
     * @param bool $allow_implicit_flow Allow OAuth 2 implicit flow. - @see http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
     * @param JWKSet|null $jwks JWKSet to use for JWT validation (can be null if you use auto discovery)
     * @throws ConnectionException
     * @noinspection SensitiveParameterInspection
     */
    public function __construct(
        public ?string $client_id = null,
        #[SensitiveParameter] public ?string $client_secret = null,
        public readonly ?string $provider_url = null,
        public ?string $issuer = null,
        public readonly array $scopes = [Scope::OPENID],
        public ?string $redirect_uri = null,
        public readonly bool $enable_pkce = true,
        public readonly bool $enable_nonce = true,
        public CodeChallengeMethod $code_challenge_method = CodeChallengeMethod::PLAIN,
        public readonly int $time_drift = 300,
        public array $response_types = [],
        public array $id_token_signing_alg_values_supported = [],
        public ?string $authorization_endpoint = null,
        public ?string $token_endpoint = null,
        public ?string $userinfo_endpoint = null,
        public ?string $end_session_endpoint = null,
        public ?string $registration_endpoint = null,
        public ?string $introspect_endpoint = null,
        public ?string $revocation_endpoint = null,
        public ?string $jwks_endpoint = null,
        public bool $authorization_response_iss_parameter_supported = false,
        public array $token_endpoint_auth_methods_supported = [],
        public readonly ?string $http_proxy = null,
        public readonly ?string $cert_path = null,
        public readonly bool $verify_ssl = true,
        public readonly int $timeout = 0,
        public readonly string $client_name = 'OpenID Connect Client',
        public readonly bool $allow_implicit_flow = false,
        public ?JWKSet $jwks = null
    ) {
        $this->redirect_uri ??= Request::capture()->url();
        $this->issuer ??= $this->provider_url;
        $this->autoDiscovery($this->provider_url);
    }

    /**
     * Custom setter for provider_url
     *
     * @param string $name Property name
     * @param mixed $value Property value
     */
    public function __set(string $name, mixed $value): void
    {
        $old_value = $this->{$name};
        $value = match ($name) {
            'provider_url' => $this->trimDiscoveryPath(rtrim($value, '/')),
            default => $value
        };
        $this->{$name} = $value;

        if ($name === 'provider_url' && $old_value !== $this->issuer) {
            $this->issuer = $value;
        }
    }

    /**
     * Authenticate the user
     *
     * @throws OIDCClientException
     * @throws Exception
     */
    public function authenticate(): bool
    {
        $request = Request::capture();

        $this->validateCallback($request);

        // If we have an authorization code, then proceed to request a token.
        $code = $request->get('code');
        if ($code) {
            return $this->token($request, $code);
        }

        $id_token = $request->get('id_token');
        if ($this->allow_implicit_flow && $id_token) {
            $this->implicitFlow($request, $id_token);
        }

        $this->requestAuthorization();
    }

    /**
     * Validate the callback request
     *
     * @param Request $request The request object
     * @throws OIDCClientException If the request is invalid
     */
    private function validateCallback(Request $request): void
    {
        // protect against mix-up attacks
        // experimental feature, see https://tools.ietf.org/html/draft-ietf-oauth-iss-auth-resp-00
        if ($this->authorization_response_iss_parameter_supported && $request->hasAny(['error', 'code', 'id_token'])
            && $request->get('iss') === $this->issuer
        ) {
            throw new OIDCClientException('Error: validation of iss response parameter failed');
        }

        // Do a preemptive check to see if the provider has thrown an error from a previous redirect.
        if ($request->has('error')) {
            $description = ' Description: ' . $request->get('error_description', 'No description provided');
            throw new OIDCClientException('Error: ' . $request->get('error') . $description);
        }
    }

    /**
     * It calls the end-session endpoint of the OpenID Connect provider to notify the OpenID
     * Connect provider that the end-user has logged out of the relying party site
     * (the client application).
     *
     * @param string $id_token ID token (got at login)
     * @param string|null $redirect URL to which the RP is requesting that the End-User's User Agent
     * be redirected after a logout has been performed. The value MUST have been previously
     * registered with the OP. Value can be null.
     *
     */
    #[NoReturn]
    public function signOut(#[SensitiveParameter] string $id_token, ?string $redirect = null): void
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
     * @throws ConnectionException
     * @noinspection SensitiveParameterInspection
     */
    public function requestTokenExchange(
        #[SensitiveParameter] string $subjectToken,
        string $subjectTokenType,
        string $audience = ''
    ): Collection {
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
     * @throws OIDCClientException|ConnectionException
     */
    public function getUserInfo(): UserInfo
    {
        $response = $this->client()
            ->withToken($this->access_token)
            ->acceptJson()
            ->get($this->userinfo_endpoint, ['schema' => 'openid']);

        if (!$response->ok()) {
            throw new OIDCClientException(
                'The communication to retrieve user data has failed with status code ' . $response->body()
            );
        }

        return new UserInfo($response->collect()->put('id_token', $this->id_token));
    }

    /**
     * Redirects the user to the given URL
     *
     * @param string $url The URL to redirect to
     */
    #[NoReturn]
    public function redirect(string $url): void
    {
        header('Location: ' . $url);
        exit;
    }

    /**
     * Get client credentials as an array
     */
    public function getClientCredentials(): array
    {
        return [$this->client_id, $this->client_secret];
    }

    /**
     * Creates a new instance of the HTTP client
     *
     * @noinspection PhpIncompatibleReturnTypeInspection - False positive
     */
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
     * Get the scope string from the scopes array
     *
     * @param array<string|Scope> $additional_scopes
     */
    private function getScopeString(array $additional_scopes = []): string
    {
        $scopes = [...$this->scopes, ...$additional_scopes];
        return implode(
            ' ',
            array_map(static fn(string|Scope $scope) => $scope instanceof Scope ? $scope->value : $scope, $scopes)
        );
    }
}
