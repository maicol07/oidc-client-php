<?php /*
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
 */ /*
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
 */ /*
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
 */ /** @noinspection ForgottenDebugOutputInspection */

/** @noinspection LaravelFunctionsInspection */

namespace Maicol07\OpenIDConnect\Tests;

use cse\helpers\Session;
use Exception;
use Facebook\WebDriver\Exception\NoSuchElementException;
use Facebook\WebDriver\Exception\TimeoutException;
use Facebook\WebDriver\WebDriverBy;
use Illuminate\Http\Request;
use JetBrains\PhpStorm\NoReturn;
use Maicol07\OpenIDConnect\Client;
use PHPUnit\Framework\Attributes\Depends;
use ReflectionException;

/**
 * OIDC Client tests
 */
class ClientTest extends TestCase
{
    /**
     * Tests user authorization URL generation
     * @throws Exception
     */
    public function testAuthorizationUrlGeneration(): string {
        $url = $this->client()->getAuthorizationUrl();
        $this->assertIsString($url);

        $code_verifier = Session::get('oidc_code_verifier');
        echo "Authorization URL: $url\nCode verifier: $code_verifier";

        if ($this->client()->verify_ssl && str_starts_with($this->client()->provider_url, "https")) {
            $this->assertStringStartsWith('https://', $url);
        } else {
            /** @noinspection HttpUrlsUsage */
            $this->assertStringStartsWith('http://', $url);
        }
        return $url;
    }

    /**
     * Tests user authorization
     *
     * @param string $url The authorization URL
     * @return array The redirect URI parameters
     * @throws NoSuchElementException If the username or password field is not found with the given selectors.
     * @throws TimeoutException If the redirect URI page has not loaded in 5 seconds after submitting the form.
     */
    #[Depends('testAuthorizationUrlGeneration')]
    public function testAuthorization(string $url): array
    {
        $driver = $this->webdriver();

        if (env('OIDC_CASDOOR_AIO')) {
            $url = str_replace('localhost:7001', 'localhost:8000', $url);
        }

        $driver->get($url);
        $driver
            ->findElement(WebDriverBy::cssSelector(env('OIDC_AUTHORIZATION_USERNAME_FIELD_SELECTOR', '[name="username"]')))
            ->sendKeys(env('OIDC_AUTHORIZATION_USERNAME'));
        $driver
            ->findElement(WebDriverBy::cssSelector(env('OIDC_AUTHORIZATION_PASSWORD_FIELD_SELECTOR', '[type="password"]')))
            ->sendKeys(env('OIDC_AUTHORIZATION_PASSWORD'))
            ->submit();

        $redirect_uri = $this->client()->redirect_uri;
        $driver->wait(5)->until(fn ($driver): bool => str_starts_with($driver->getCurrentURL(), $redirect_uri));

        $url = $driver->getCurrentURL();
        $paramsString = parse_url($url)[$this->client()->allow_implicit_flow ? 'fragment' : 'query'];
        parse_str($paramsString, $params);

        $driver->quit();

        dump($this->client()->allow_implicit_flow ? 'IMPLICIT FLOW' : 'STANDARD FLOW', $params);
        if (!$this->client()->allow_implicit_flow) {
            $this->assertArrayHasKey('code', $params);
        }
        $this->assertArrayHasKey('state', $params);

        $params['session_state'] = Session::get('oidc_state');
        $params['session_nonce'] = Session::get('oidc_nonce');

        return $params;
    }

    /**
     * Tests token request
     *
     * @param array $params The redirect URI parameters
     * @return Client The client instance
     * @throws ReflectionException If the method or property does not exist.
     */
    #[Depends('testAuthorization')]
    public function testToken(array $params): Client {
        if ($this->client()->allow_implicit_flow) {
            $this->markTestSkipped('Implicit flow is enabled.');
        }

        if (env('OIDC_CODE_VERIFIER')) {
            Session::set('oidc_code_verifier', env('OIDC_CODE_VERIFIER'));
        }
        if (env('OIDC_STATE')) {
            Session::set('oidc_state', env('OIDC_STATE'));
        }
        $request = Request::create('', parameters: ['code' => env('OIDC_AUTHORIZATION_CODE', $params['code']), 'state' => env('OIDC_STATE', $params['state'])]);
        $result = $this->invokeMethod($this->client(), 'token', [$request, env('OIDC_AUTHORIZATION_CODE', $params['code'])]);
        $this->assertTrue($result);

        $access_token = $this->getProperty($this->client(), 'access_token');
        $refresh_token = $this->getProperty($this->client(), 'refresh_token');
        $id_token = $this->getProperty($this->client(), 'id_token');

        $this->assertIsString($access_token);
        $this->assertIsString($refresh_token);
        $this->assertIsString($id_token);


        dump("Tokens:\nAccess token: $access_token\nRefresh token: $refresh_token\nID token: $id_token");
        return $this->client();
    }

    /**
     * Tests user info request
     *
     * @param Client $client The client instance
     */
    #[Depends('testToken')]
    public function testUserInfo(Client $client): void {
        $user = $client->getUserInfo();
        $this->assertIsString($user->id_token);
        $this->assertIsString($user->sub);

        dump($user);
    }

    /**
     * Tests token introspection
     *
     * @param Client $client The client instance
     */
    #[NoReturn] #[Depends('testToken')]
    public function testTokenIntrospection(Client $client): void {
        if ($client->allow_implicit_flow) {
            $this->markTestSkipped('Implicit flow is enabled.');
        }
        $access_token = $this->getProperty($client, 'access_token');
        $refresh_token = $this->getProperty($client, 'refresh_token');
        $id_token = $this->getProperty($client, 'id_token');
        $result_access_token = $client->introspectToken($access_token);
        $result_refresh_token = $client->introspectToken($refresh_token);
        $result_id_token = $client->introspectToken($id_token);

        dump($result_access_token, $result_refresh_token, $result_id_token);

        $this->assertIsBool($result_access_token->get('active'));
        $this->assertIsBool($result_refresh_token->get('active'));
        $this->assertIsBool($result_id_token->get('active'));
    }

    /**
     * Tests OIDC implicit flow
     *
     * @param array $params The redirect URI parameters
     * @return Client The client instance
     * @throws ReflectionException If the method or property does not exist.
     */
    #[Depends('testAuthorization')]
    public function testImplicitFlow(array $params): Client {
        if (!$this->client()->allow_implicit_flow) {
            $this->markTestSkipped('Implicit flow is disabled.');
        }

        if (env('OIDC_STATE')) {
            Session::set('oidc_state', env('OIDC_STATE'));
        }

        if (!Session::has('oidc_state')) {
            Session::set('oidc_state', $params['session_state']);
        }

        if (!Session::has('oidc_nonce')) {
            Session::set('oidc_nonce', $params['session_nonce']);
        }

        $request = Request::create('', parameters: [
            'state' => env('OIDC_STATE', $params['state']),
            'id_token' => env('OIDC_ID_TOKEN', $params['id_token']),
            'access_token' => env('OIDC_ACCESS_TOKEN', $params['access_token']),
            'token_type' => env('OIDC_TOKEN_TYPE', $params['token_type']),
            'expires_in' => env('OIDC_EXPIRES_IN', $params['expires_in']),
            'scope' => env('OIDC_SCOPE', $params['scope'])
        ]);
        $result = $this->invokeMethod($this->client(), 'implicitFlow', [$request, env('OIDC_ID_TOKEN', $params['id_token'])]);
        $this->assertTrue($result);

        $access_token = $this->getProperty($this->client(), 'access_token');
        $id_token = $this->getProperty($this->client(), 'id_token');

        $this->assertIsString($access_token);
        $this->assertIsString($id_token);

        dump("Tokens:\nAccess token: $access_token\nID token: $id_token");
        return $this->client();
    }

    /**
     * Tests user info request with implicit flow
     *
     * @param Client $client The client instance
     */
    #[Depends('testImplicitFlow')]
    public function testUserInfoImplicitFlow(Client $client): void {
        $user = $client->getUserInfo();
        $this->assertIsString($user->id_token);
        $this->assertIsString($user->sub);

        dump($user);
    }

    /**
     * Tests token introspection with implicit flow
     *
     * @param Client $client The client instance
     */
    #[NoReturn] #[Depends('testImplicitFlow')]
    public function testTokenIntrospectionImplicitFlow(Client $client): void {
        $access_token = $this->getProperty($client, 'access_token');
        $id_token = $this->getProperty($client, 'id_token');
        $result_access_token = $client->introspectToken($access_token);
        $result_id_token = $client->introspectToken($id_token);

        dump($result_access_token, $result_id_token);

        $this->assertIsBool($result_access_token->get('active'));
        $this->assertIsBool($result_id_token->get('active'));
    }

    /**
     * Tests dynamic registration
     */
    public function testDynamicRegistration(): void {
        $this->client()->register();
        dump($this->client()->client_id, $this->client()->client_secret);

        $this->assertIsString($this->client()->client_id);
        $this->assertIsString($this->client()->client_secret);
    }
}
