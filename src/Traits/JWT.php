<?php

/** @noinspection PhpUnusedPrivateMethodInspection */

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

namespace Maicol07\OpenIDConnect\Traits;

use DateInterval;
use DateTimeZone;
use Illuminate\Support\Str;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Maicol07\OpenIDConnect\ClientException;

trait JWT
{
    private string $jwt_signing_method;
    /** @var string|null Only needed if signing method is set to RSXXX or ECXXX. */
    private ?string $jwt_signing_key;
    private ?string $jwt_key;
    private bool $jwt_plain_key;
    private int $leeway;

    private function validateJWT(string|\Lcobucci\JWT\Token $jwt): void
    {
        try {
            if (is_string($jwt)) {
                $jwt = $this->jwt()->parser()->parse($jwt);
            }
            $claims = $jwt->claims();
            if (!(
                $claims->has(RegisteredClaims::EXPIRATION_TIME)
                && $claims->has(RegisteredClaims::ISSUED_AT)
            )) {
                throw new ClientException('Missing required claims: exp, iat');
            }
            $this->jwt()->validator()->assert($jwt, ...$this->jwt()->validationConstraints());
        } catch (RequiredConstraintsViolated $e) {
            throw new ClientException(
                'JWT validation error - Invalid claims: ' . implode(', ', $e->violations())
            );
        }
    }

    private function jwt(): Configuration
    {
        $signer = match ($this->jwt_signing_method) {
            'HS256', 'sha256' => new Hmac\Sha256(),
            'HS384', 'sha384' => new Hmac\Sha384(),
            'HS512', 'sha512' => new Hmac\Sha512(),
            'RS256' => new Rsa\Sha256(),
            'RS384' => new Rsa\Sha384(),
            'RS512' => new Rsa\Sha512(),
            'EC256' => Ecdsa\Sha256::create(),
            'EC384' => Ecdsa\Sha384::create(),
            'EC512' => Ecdsa\Sha512::create(),
        };

        $key = $this->getJWTKey($this->jwt_key);

        if (Str::startsWith($this->jwt_signing_method, ['RS', 'EC'])) {
            $config = Configuration::forAsymmetricSigner($signer, $this->getJWTKey($this->jwt_signing_key), $key);
        } else {
            $config = Configuration::forSymmetricSigner($signer, $key);
        }

        $config->setValidationConstraints(
            new PermittedFor($this->client_id),
            new LooseValidAt(
                new SystemClock(
                    new DateTimeZone(date_default_timezone_get())
                ),
                new DateInterval("PT{$this->leeway}S")
            ),
            new SignedWith($config->signer(), $config->verificationKey()),
            new IssuedBy($this->issuer)
        );

        return $config;
    }

    private function getJWTKey(string $key): InMemory
    {
        if (file_exists($key)) {
            return InMemory::file($key);
        }

        if ($this->jwt_plain_key) {
            return InMemory::plainText($key);
        }

        return InMemory::base64Encoded($key);
    }
}
