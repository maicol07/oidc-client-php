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
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\RSAKey;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Maicol07\OpenIDConnect\ClientException;
use Maicol07\OpenIDConnect\JwtSigningAlgorithm;

trait JWT
{
    private JwtSigningAlgorithm $jwt_signing_algorithm = JwtSigningAlgorithm::HS256;
    /** Only needed if signing method is set to RSXXX or ECXXX. */
    private ?string $jwt_signing_key = null;
    /** Only needed if signing method is set to RSXXX or ECXXX. */
    private string|JWK $jwt_verification_key = '';
    /** Either plain or base64 encoded key */
    private ?string $jwt_key = null;
    private bool $jwt_base64_encoded_key = false;
    private int $leeway = 300;
    private string $jwk_kid = '';
    private ?JWKSet $jwks = null;
    private ?string $jwk_endpoint = null;

    /**
     * Set an asymmetric key to verify the signature of the JWT.
     *
     * @param string $signing_key The public key used to sign the JWT
     * @param string $encoding_key The private key used to verify the JWT signature
     */
    public function jwtAsymmetricKey(string $signing_key, string $encoding_key): self
    {
        $this->jwt_signing_key = $signing_key;
        $this->jwt_verification_key = $encoding_key;
        return $this;
    }

    /**
     * Set a symmetric key to verify the signature of the JWT.
     *
     * @param string $key A plain or base64 encoded key
     * @param bool $base64 If the key is plain or base64 encoded
     */
    public function jwtSymmetricKey(string $key, bool $base64 = false): self
    {
        $this->jwt_key = $key;
        $this->jwt_base64_encoded_key = $base64;
        return $this;
    }

    private function validateJWT(string|\Lcobucci\JWT\Token $jwt): void
    {
        try {
            if (is_string($jwt)) {
                $jwt = $this->jwt()->parser()->parse($jwt);
            }

            if (!empty($this->jwks)) {
                $this->jwk_kid = $jwt->headers()->get('kid');
                $this->jwt_verification_key = $this->jwks->get($this->jwk_kid);
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
        $signer = $this->jwt_signing_algorithm->getSigner();

        if ($signer instanceof Rsa || $signer instanceof Ecdsa) {
            if (empty($this->jwt_verification_key) && !empty($this->jwk_endpoint)) {
                $set = $this->client()->get($this->jwk_endpoint)->json();
                $this->jwks = JWKSet::createFromKeyData($set);
            }

            $config = Configuration::forAsymmetricSigner($signer, $this->getJWTKey($this->jwt_signing_key), $this->getJWTKey($this->jwt_verification_key));
        } else {
            $config = Configuration::forSymmetricSigner($signer, $this->getJWTKey($this->jwt_key));
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

    private function getJWTKey(string|JWK $key): Key
    {
        if ($key instanceof JWK) {
            return new \Maicol07\OpenIDConnect\Jwk\Jwk($key);
        }

        if (file_exists($key)) {
            return InMemory::file($key);
        }

        if ($this->jwt_base64_encoded_key) {
            return InMemory::base64Encoded($key);
        }

        return InMemory::plainText($key);
    }
}
