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

/** @noinspection UnknownInspectionInspection, LaravelFunctionsInspection */

namespace Maicol07\OpenIDConnect\Tests;

use Facebook\WebDriver\Remote\DesiredCapabilities;
use Facebook\WebDriver\Remote\RemoteWebDriver;
use Maicol07\OpenIDConnect\Client;
use Maicol07\OpenIDConnect\CodeChallengeMethod;
use Maicol07\OpenIDConnect\Scope;
use ReflectionClass;
use ReflectionException;

require_once __DIR__ . '/../vendor/autoload.php';

/**
 * Base test case class
 */
abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    /** An instance of the client */
    private Client $client;
    /** An instance of the webdriver */
    private RemoteWebDriver $webdriver;

    /**
     * Get an instance of the client
     *
     * @return Client The client instance
     */
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

    /**
     * Get an instance of the webdriver
     *
     * @param string|null $browser The browser to use. Default: env('OIDC_BROWSER')
     *
     * @return RemoteWebDriver The webdriver instance
     */
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
     * @param string|object $object &$object Instantiated object that we will run method on.
     * @param string $methodName Method name to call
     * @param array $parameters Array of parameters to pass into method.
     *
     * @return mixed Method return.
     * @throws ReflectionException
     */
    public function invokeMethod(string|object $object, string $methodName, array $parameters = []): mixed
    {
        $method = (new ReflectionClass(get_class($object)))->getMethod($methodName);
        /** @noinspection PhpExpressionResultUnusedInspection */
        $method->setAccessible(true);

        return $method->invokeArgs($object, $parameters);
    }

    /**
     * Get a protected/private property of a class.
     *
     * @param object $object An instantiated object that we will run method on.
     * @param string $propertyName Property name to get
     * @return mixed Property value.
     * @throws ReflectionException If the property doesn't exist.
     */
    public function getProperty(object $object, string $propertyName): mixed
    {
        return (new ReflectionClass(get_class($object)))->getProperty($propertyName)->getValue($object);
    }
}
