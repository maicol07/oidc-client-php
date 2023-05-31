<?php
/** @noinspection UnknownInspectionInspection, LaravelFunctionsInspection */

namespace Maicol07\OpenIDConnect\Tests;

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

use Facebook\WebDriver\Remote\DesiredCapabilities;
use Facebook\WebDriver\Remote\RemoteWebDriver;
use Maicol07\OpenIDConnect\Client;
use Maicol07\OpenIDConnect\CodeChallengeMethod;
use Maicol07\OpenIDConnect\JwtSigningAlgorithm;
use Maicol07\OpenIDConnect\Scope;
use ReflectionClass;
use ReflectionException;

require_once __DIR__ . '/../vendor/autoload.php';

abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    private Client $client;
    private RemoteWebDriver $webdriver;
    protected function client(): Client {
        $this->client ??= new Client(
            client_id: env('OIDC_CLIENT_ID'),
            client_secret: env('OIDC_CLIENT_SECRET'),
            provider_url: env('OIDC_PROVIDER_URL'),
            scopes: [Scope::OPENID, Scope::EMAIL, Scope::PROFILE],
            redirect_uri: env('OIDC_REDIRECT_URI'),
            enable_pkce: env('OIDC_ENABLE_PKCE'),
            code_challenge_method: env('OIDC_CODE_CHALLENGE_METHOD') === 'S256' ? CodeChallengeMethod::S256 : CodeChallengeMethod::PLAIN,
            client_name: env('OIDC_CLIENT_NAME', 'OIDC Client PHP'),
            allow_implicit_flow: env('OIDC_ALLOW_IMPLICIT_FLOW', false),
        );
        $this->assertInstanceOf(Client::class, $this->client);
        return $this->client;
    }

    public function webdriver(?string $browser = null): RemoteWebDriver {
        if ($browser === null) {
            $browser = env('OIDC_BROWSER');
        }

        $capability = match ($browser) {
            'chrome' => DesiredCapabilities::chrome(),
            'firefox' => DesiredCapabilities::firefox(),
            default => DesiredCapabilities::microsoftEdge(),
        };

        $driver = RemoteWebDriver::create(env('OIDC_SELENIUM_URL', 'http://localhost:4444'), $capability);

        $this->webdriver ??= $driver;
        if ($this->webdriver->getCapabilities()->getBrowserName() === $capability->getBrowserName()) {
            $this->webdriver = $driver;
        }

        return $this->webdriver;
    }

    /**
     * Call protected/private method of a class.
     *
     * @param object &$object Instantiated object that we will run method on.
     * @param string $methodName Method name to call
     * @param array $parameters Array of parameters to pass into method.
     *
     * @return mixed Method return.
     * @throws ReflectionException
     */
    public function invokeMethod(string|object $object, string $methodName, array $parameters = []): mixed
    {
        $reflection = new ReflectionClass(get_class($object));
        $method = $reflection->getMethod($methodName);
        /** @noinspection PhpExpressionResultUnusedInspection */
        $method->setAccessible(true);

        return $method->invokeArgs($object, $parameters);
    }

    public function getProperty(object $object, string $propertyName): mixed
    {
        $reflection = new ReflectionClass(get_class($object));
        $property = $reflection->getProperty($propertyName);
//        /** @noinspection PhpExpressionResultUnusedInspection */
//        $property->setAccessible(true);
        return $property->getValue($object);
    }
}
