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
use JetBrains\PhpStorm\NoReturn;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Maicol07\OpenIDConnect\Traits\Authorization;
use Maicol07\OpenIDConnect\Traits\AutoDiscovery;
use Maicol07\OpenIDConnect\Traits\DynamicRegistration;
use Maicol07\OpenIDConnect\Traits\ImplictFlow;
use Maicol07\OpenIDConnect\Traits\JWT;
use Maicol07\OpenIDConnect\Traits\Token;

class Client
{
    use Authorization;
    use Token;
    use AutoDiscovery;
    use DynamicRegistration;
    use ImplictFlow;
    use JWT;

    private string $access_token;
    private string $id_token;

    /**
     * @param string $client_id
     * @param string $client_secret
     * @param string|null $provider_url
     * @param string|null $issuer
     * @param array<string|Scope> $scopes
     * @param string|null $redirect_uri
     * @param bool $enable_pkce
     * @param bool $enable_nonce
     * @param bool $allowImplicitFlow
     * @param CodeChallengeMethod $code_challenge_method Code challenge method for PKCE mode - @see https://tools.ietf.org/html/rfc7636
     * @param int $leeway
     * @param ResponseType[] $response_types
     * @param JwtSigningAlgorithm[] $id_token_signing_alg_values_supported
     * @param string|JWK|null $jwt_verification_key Public key used to sign the JWT. Only needed if signing method is set to RSXXX or ECXXX.
     * @param string|null $jwt_signing_key Private key used to verify the JWT signature. Only needed if signing method is set to RSXXX or ECXXX.
     * @param string|null $authorization_endpoint
     * @param string|null $token_endpoint
     * @param string|null $userinfo_endpoint
     * @param string|null $end_session_endpoint
     * @param string|null $registration_endpoint
     * @param string|null $introspect_endpoint
     * @param string|null $revocation_endpoint
     * @param string|null $jwks_endpoint
     * @param bool $authorization_response_iss_parameter_supported
     * @param ClientAuthMethod[] $token_endpoint_auth_methods_supported
     * @param string|null $http_proxy
     * @param string|null $cert_path
     * @param bool $verify_ssl
     * @param int $timeout
     * @param string $client_name
     * @param bool $allow_implicit_flow Allow OAuth 2 implicit flow. - @see http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
     * @param string|null $jwt_key Symmetric JWT key used to decode the token (can be plain text or base64 encoded). Defaults to client secret
     * @param bool $jwt_base64_encoded_key Whether the key is base64 encoded
     * @param JWKSet|null $jwks
     */
    public function __construct(
        public string $client_id,
        public string $client_secret,
        public readonly ?string $provider_url = null,
        public ?string $issuer = null,
        public readonly array $scopes = [Scope::OPENID],
        public ?string $redirect_uri = null,
        public readonly bool $enable_pkce = true,
        public readonly bool $enable_nonce = true,
        public readonly bool $allowImplicitFlow = false,
        public CodeChallengeMethod $code_challenge_method = CodeChallengeMethod::PLAIN,
        public readonly int $leeway = 300,
        public array $response_types = [],
        public array $id_token_signing_alg_values_supported = [],
        public string|JWK|null $jwt_verification_key = null,
        public ?string $jwt_signing_key = null,
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
        public readonly ?string $jwt_key = null,
        public readonly bool $jwt_base64_encoded_key = false,
        public ?JWKSet $jwks = null
    ) {
        $this->redirect_uri ??= Request::capture()->url();
        $this->autoDiscovery($this->provider_url);
    }

    public function __set(string $name, mixed $value): void
    {
        $value = match ($name) {
            'provider_url' => $this->trimDiscoveryPath(rtrim($value, '/')),
            default => $value
        };
        $this->{$name} = $value;

        if ($name === 'provider_url') {
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
    public function requestTokenExchange(
        string $subjectToken,
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
     * @throws OIDCClientException
     */
    public function getUserInfo(): UserInfo
    {
        $response = (new Factory())->withToken($this->access_token)
            ->acceptJson()
            ->get($this->userinfo_endpoint, ['schema' => 'openid']);

        if (!$response->ok()) {
            throw new OIDCClientException(
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

    /** @noinspection PhpIncompatibleReturnTypeInspection - False positive */
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
        $scopes = [...$this->scopes, ...$additional_scopes];
        return implode(
            ' ',
            array_map(static fn(string|Scope $scope) => $scope instanceof Scope ? $scope->value : $scope, $scopes)
        );
    }
}
