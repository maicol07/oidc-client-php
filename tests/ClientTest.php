<?php /** @noinspection LaravelFunctionsInspection */

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

namespace Maicol07\OpenIDConnect\Tests;

use cse\helpers\Session;
use Facebook\WebDriver\WebDriverBy;
use Facebook\WebDriver\WebDriverExpectedCondition;
use Illuminate\Http\Request;
use Maicol07\OpenIDConnect\Client;
use Maicol07\OpenIDConnect\UserInfo;
use PHPUnit\Framework\Attributes\Depends;

class ClientTest extends TestCase
{
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
        $driver->wait(5)->until(fn ($driver) => str_starts_with($driver->getCurrentURL(), $redirect_uri));

        $url = $driver->getCurrentURL();
        $query = parse_url($url)['query'];
        echo "Callback query: $query";
        parse_str($query, $params);

        $driver->quit();

        dump($params);
        $this->assertArrayHasKey('code', $params);
        $this->assertArrayHasKey('state', $params);

        return $params;
    }

    #[Depends('testAuthorization')]
    public function testToken(array $params): Client {
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

    #[Depends('testToken')]
    public function testUserInfo(Client $client): bool {
        $user = $client->getUserInfo();
        $this->assertIsString($user->id_token);

        dump($user);
        return true;
    }
}
