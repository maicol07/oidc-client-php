<?php
/** @noinspection PhpUnused */
/** @noinspection PhpPropertyOnlyWrittenInspection */

namespace Maicol07\OIDCClient;

use DateInterval;
use DateTimeZone;
use Exception;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Delight\Cookie\Session;
use Illuminate\Support\Str;
use JetBrains\PhpStorm\ArrayShape;
use JetBrains\PhpStorm\NoReturn;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use function bin2hex;
use function random_bytes;

/**
 * OpenIDConnect Exception Class
 */
class OpenIDConnectClientException extends Exception
{
}

/**
 *
 * Please note this class stores nonces by default in $_SESSION['openid_connect_nonce']
 *
 */
class OIDCClient
{
    private string $client_id;
    private string $client_name;
    private string $client_secret;
    private ?string $issuer;
    private string $access_token;
    private string $refresh_token;
    private string $id_token;
    private array $scopes;
    private array $response_types;
    private int $leeway;
    /** Allow OAuth 2 implicit flow; see http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth */
    private bool $allow_implicit_flow = false;
    private string $redirect_uri;

    /**
     * @var string holds code challenge method for PKCE mode
     * @see https://tools.ietf.org/html/rfc7636
     */
    private string $code_challenge_method;
    private array $pkce_algorithms = ['S256' => 'sha256', 'plain' => false];
    private bool $enable_pkce;
    private bool $send_nonce;

    private PendingRequest $http_client;

    // Endpoints
    private string $authorization_endpoint;
    private bool $authorization_response_iss_parameter_supported;
    private string $token_endpoint;
    private array $token_endpoint_auth_methods_supported;
    private string $userinfo_endpoint;
    private ?string $end_session_endpoint;
    private ?string $registration_endpoint;
    private ?string $introspect_endpoint;
    private ?string $revocation_endpoint;

    private string $jwt_signing_method;
    private ?string $jwt_key;
    private bool $jwt_plain_key;

    /**
     * @param array $user_config Config for the OIDC Client. The missing config values will be retrieved from the provider via auto-discovery if the `provider_url` exists and the auto-discovery endpoint is supported.
     */
    public function __construct(#[ArrayShape([
        'client_id' => 'string',
        'client_secret' => 'string',
        'provider_url' => '?string',
        'issuer' => '?string',
        'http_proxy' => '?string',
        'cert_path' => '?string',
        'verify' => '?bool',
        'scopes' => '?array',
        'enable_pkce' => '?bool',
        'send_nonce' => '?bool',
        'allow_implicit_flow' => '?bool',
        'code_challenge_method' => '?string',
        'timeout' => '?int',
        'leeway' => '?int',
        'redirect_uri' => 'string',
        'response_types' => '?array',
        'authorization_endpoint' => '?string',
        'authorization_response_iss_parameter_supported' => '?bool',
        'token_endpoint' => '?string',
        'token_endpoint_auth_methods_supported' => '?array',
        'userinfo_endpoint' => '?string',
        'end_session_endpoint' => '?string',
        'registration_endpoint' => '?string',
        'introspect_endpoint' => '?string',
        'revocation_endpoint' => '?string',
        'jwt_signing_method' => '?string',
        'jwt_key' => 'string',
        'jwt_plain_key' => '?bool'
    ])] array $user_config)
    {
        $this->http_client = (new Factory())->withOptions([
            'connect_timeout' => Arr::get($user_config, 'timeout', 0),
            'proxy' => Arr::get($user_config, 'http_proxy'),
            'verify' => Arr::get($user_config, 'verify') ?: (Arr::get($user_config, 'cert_path', false))
        ]);

        // Auto discovery
        $provider_url = rtrim(Arr::get($user_config, 'provider_url'), '/');

        if ($provider_url) {
            $response = $this->http_client->get(
                "$provider_url/.well-known/openid-configuration",
                Arr::get($user_config, 'well_known_request_params')
            );
            if ($response->ok()) {
                $config = $response->collect()->mergeRecursive($user_config);
            }
        }

        $config ??= collect($user_config);

        $props = [
            'client_id' => null,
            'client_secret' => null,
            'issuer' => $provider_url,
            'scopes' => [],
            'enable_pkce' => true,
            'send_nonce' => true,
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
            'jwt_signing_method' => 'sha256',
            'jwt_key' => Arr::get($config, 'client_secret'),
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
     * @throws OpenIDConnectClientException
     * @throws Exception
     */
    public function authenticate(): bool
    {
        $request = Request::capture();

        // protect against mix-up attacks
        // experimental feature, see https://tools.ietf.org/html/draft-ietf-oauth-iss-auth-resp-00
        if ($this->authorization_response_iss_parameter_supported && $request->hasAny(['error', 'code', 'id_token'])
            && $request->get('iss') === $this->issuer
        ) {
            throw new OpenIDConnectClientException('Error: validation of iss response parameter failed');
        }

        // Do a preemptive check to see if the provider has thrown an error from a previous redirect.
        if ($request->has('error')) {
            $description = ' Description: ' . $request->get('error_description', 'No description provided');
            throw new OpenIDConnectClientException('Error: ' . $request->get('error') . $description);
        }

        $jwt_config = $this->jwt();

        // If we have an authorization code then proceed to request a token
        $code = $request->get('code');
        if ($code) {
            $token_response = $this->requestTokens($code);

            // Throw an error if the server returns one
            $error = $token_response->get('error');
            if ($error) {
                $description = $token_response->get('error_description');
                throw new OpenIDConnectClientException($description ?: ('Got response: ' . $error));
            }

            // Do an OpenID Connect session check
            if ($request->get('state') !== Session::take('oidc_state')) {
                throw new OpenIDConnectClientException('Unable to determine state');
            }

            if (!$token_response->has('id_token')) {
                throw new OpenIDConnectClientException('User did not authorize openid scope.');
            }

            if (Session::take('oidc_nonce') !== $request->get('nonce')) {
                throw new OpenIDConnectClientException("Generated nonce is not equal to the one returned by the server.");
            }

            try {
                $jwt = $jwt_config->parser()->parse($token_response->get('id_token'));
                $jwt_config->validator()->assert($jwt, ...$jwt_config->validationConstraints());
            } catch (RequiredConstraintsViolated $e) {
                throw new OpenIDConnectClientException('JWT validation error - Claims not valid: ' . implode(', ', $e->violations()));
            }

            $this->id_token = $token_response->get('id_token');
            $this->access_token = $token_response->get('access_token');
            $this->refresh_token = $token_response->get('refresh_token');

            return true;
        }

        $id_token = $request->get('id_token');
        if ($this->allow_implicit_flow && $id_token) {
            $this->access_token = $request->get('access_token');

            // Do an OpenID Connect session check
            if ($request->get('state') !== Session::take('oidc_state')) {
                throw new OpenIDConnectClientException('Unable to determine state');
            }

            try {
                $jwt = $jwt_config->parser()->parse($id_token);
                $jwt_config->validator()->assert($jwt, ...$jwt_config->validationConstraints());
            } catch (RequiredConstraintsViolated $e) {
                throw new OpenIDConnectClientException('JWT validation error - Claims not valid: ' . implode(', ', $e->violations()));
            }

            // Save the id token
            $this->id_token = $id_token;

            if ($request->get('nonce') === Session::take('oidc_nonce')) {
                return true;
            }

            throw new OpenIDConnectClientException('Unable to verify JWT claims');
        }

        $this->requestAuthorization();
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
    public function signOut(string $id_token, ?string $redirect=null): void
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
     * Get the authorization URL
     *
     * @throws Exception
     */
    public function getAuthorizationUrl(?array $query_params=null): string
    {
        $auth_endpoint = $this->authorization_endpoint;

        // State essentially acts as a session key for OIDC
        $state = Str::random();
        Session::set('oidc_state', $state);

        $params = collect([
            'response_type' => 'code',
            'redirect_uri' => $this->redirect_uri,
            'client_id' => $this->client_id,
            'state' => $state,
            'scope' => implode(' ', array_merge($this->scopes, ['openid']))
        ])->merge($query_params);

        if ($this->send_nonce) {
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
        if ($this->enable_pkce && !empty($this->code_challenge_method) && (empty($this->response_types) || count(array_diff($this->response_types, ['token', 'id_token'])) > 0)
        ) {
            // Generate a cryptographically secure code
            $code_verifier = bin2hex(random_bytes(64));
            Session::set('oidc_code_verifier', $code_verifier);
            $code_challenge = !empty($this->pkce_algorithms[$this->code_challenge_method]) ?
                rtrim(strtr(base64_encode(hash($this->pkce_algorithms[$this->code_challenge_method], $code_verifier, true)), '+/', '-_'), '=') :
                $code_verifier;
            $params->put('code_challenge', $code_challenge)->put('code_challenge_method', $this->code_challenge_method);
        }

        $auth_endpoint .= (!str_contains($auth_endpoint, '?') ? '?' : '&') . Arr::query($params->all());
        return $auth_endpoint;
    }

    /**
     * Start Here
     *
     * @throws OpenIDConnectClientException
     * @throws Exception
     */
    #[NoReturn]
    private function requestAuthorization(): void
    {
        $auth_endpoint = $this->getAuthorizationUrl();

        Session::start();
        $this->redirect($auth_endpoint);
    }

    /**
     * Requests ID and Access tokens
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
        $http_client = $this->http_client;
        if (in_array('client_secret_basic', $this->token_endpoint_auth_methods_supported, true)) {
            $http_client = $http_client->withBasicAuth($this->client_id, $this->client_secret);
            unset($data['client_secret'], $data['client_id']);
        }

        $code_verifier = Session::get('oidc_code_verifier');
        if ($this->enable_pkce && !empty($this->code_challenge_method) && !empty($code_verifier)) {
            $data['code_verifier'] = $code_verifier;
        }

        return $http_client->post($this->token_endpoint, $data)->collect();
    }

    /**
     * Requests Access token with refresh token
     *
     * @param bool $send_scopes (optional) Controls whether scopes are sent in the request, defaults to true
     */
    public function refreshToken(string $refresh_token, bool $send_scopes = true): Collection
    {
        $data = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refresh_token,
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
        ];

        if ($send_scopes) {
            $data['scopes'] = implode(' ', $this->scopes);
        }

        $http_client = $this->http_client;

        // Consider Basic authentication if provider config is set this way
        if (in_array('client_secret_basic', $this->token_endpoint_auth_methods_supported, true)) {
            $http_client = $http_client->withBasicAuth($this->client_id, $this->client_secret);
            unset($data['client_secret'], $data['client_id']);
        }

        $response = $http_client->post($this->token_endpoint, $data)->collect();

        $this->access_token = $response->get('access_token');
        $this->refresh_token = $response->get('refresh_token');

        return $response;
    }

    /**
     * @throws Exception
     */
    private function jwt(): Configuration
    {
        $signer = match ($this->jwt_signing_method) {
            'sha256' => new Hmac\Sha256(),
            'sha384' => new Hmac\Sha384(),
            'sha512' => new Hmac\Sha512()
        };

        $config = Configuration::forSymmetricSigner(
            $signer,
            $this->jwt_plain_key ? InMemory::plainText($this->jwt_key) : InMemory::base64Encoded($this->jwt_key)
        );

        $config->setValidationConstraints(
            new PermittedFor($this->client_id),
            new StrictValidAt(new SystemClock(new DateTimeZone(date_default_timezone_get())), new DateInterval("PT{$this->leeway}S")),
            new SignedWith($config->signer(), $config->signingKey()),
            new IssuedBy($this->issuer)
        );

        return $config;
    }

    /**
     * Returns the user info
     *
     * @throws OpenIDConnectClientException
     */
    public function getUserInfo(): UserInfo
    {
        $response = $this->http_client->withToken($this->access_token)
            ->acceptJson()
            ->get($this->userinfo_endpoint, ['schema' => 'openid']);

        if (!$response->ok()) {
            throw new OpenIDConnectClientException('The communication to retrieve user data has failed with status code ' . $response->body());
        }

        return new UserInfo($response->collect()->put('id_token', $this->id_token));
    }

    #[NoReturn]
    public function redirect(string $url): void
    {
        header('Location: ' . $url);
        exit;
    }

    /**
     * Dynamic registration
     *
     * @throws OpenIDConnectClientException
     */
    public function register(?array $params = null): void
    {
        $data = collect($params)
            ->put('redirect_uris', [$this->redirect_uri])
            ->put('client_name', $this->client_name);

        $response = $this->http_client->post($this->registration_endpoint, $data->all())->collect();

        $error = $response->get('error_description');
        if ($error) {
            throw new OpenIDConnectClientException($error);
        }

        $this->client_id = $response->get('client_id');

        // The OpenID Connect Dynamic registration protocol makes the client secret optional
        // and provides a registration access token and URI endpoint if it is not present
        $secret = $response->get('client_secret');
        if ($secret) {
            $this->client_secret = $secret;
        } else {
            throw new OpenIDConnectClientException('Error registering:
                                                    Please contact the OpenID Connect provider and obtain a Client ID and Secret directly from them');
        }
    }

    /**
     * Introspect a given token — either access token or refresh token.
     *
     * @link https://tools.ietf.org/html/rfc7662
     */
    public function introspectToken(string $token, string $token_type_hint = '', ?string $client_id = null, ?string $client_secret = null): Collection
    {
        $data = ['token' => $token];

        if ($token_type_hint) {
            $data['token_type_hint'] = $token_type_hint;
        }
        $client_id ??= $this->client_id;
        $client_secret ??= $this->client_secret;

        return $this->http_client
            ->withBasicAuth($client_id, $client_secret)
            ->acceptJson()
            ->post($this->introspect_endpoint, $data)
            ->collect();
    }

    /**
     * Revoke a given token - either access token or refresh token.
     *
     * @see https://tools.ietf.org/html/rfc7009
     */
    public function revokeToken(string $token, string $token_type_hint = '', ?string $client_id = null, ?string $client_secret = null): Collection
    {
        $data = ['token' => $token];

        if ($token_type_hint) {
            $data['token_type_hint'] = $token_type_hint;
        }
        $client_id ??= $this->client_id;
        $client_secret ??= $this->client_secret;

        return $this->http_client
            ->withBasicAuth($client_id, $client_secret)
            ->acceptJson()
            ->post($this->revocation_endpoint, $data)
            ->collect();
    }

    /** @noinspection GlobalVariableUsageInspection */
    public function getCurrentURL(): string
    {
        $protocol = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] === 443) ? "https://" : "http://";
        return $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    }
}
