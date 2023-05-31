<?php
/*
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
 */

/** @noinspection PhpUnusedPrivateMethodInspection */

namespace Maicol07\OpenIDConnect\Traits;

use cse\helpers\Session;
use Exception;
use Jose\Component\Checker;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use JsonException;
use Maicol07\OpenIDConnect\Checker\NonceChecker;
use Maicol07\OpenIDConnect\JwtSigningAlgorithm;

trait JWT
{
    /**
     * Loads and validates a JWT
     *
     * @throws JsonException If the JWT payload is not valid JSON
     * @throws Exception If the JWT is not valid
     */
    private function loadAndValidateJWT(string $jwt): JWS
    {
        $claimCheckerManager = new ClaimCheckerManager(
            [
                new Checker\IssuedAtChecker($this->time_drift),
                new Checker\NotBeforeChecker($this->time_drift),
                new Checker\ExpirationTimeChecker($this->time_drift),
                new Checker\AudienceChecker($this->client_id),
                new Checker\IssuerChecker([$this->issuer])
            ]
        );

        $jws = $this->jwsLoader()->loadAndVerifyWithKeySet($jwt, $this->getJWKs(), $signature);
        $claimCheckerManager->check(json_decode($jws->getPayload(), true, 512, JSON_THROW_ON_ERROR));
        Session::remove('oidc_nonce');

        return $jws;
    }

    /**
     * Creates a JWS Loader
     */
    private function jwsLoader(): JWSLoader
    {
        $algorithmManager = new AlgorithmManager(array_map(static fn (JwtSigningAlgorithm $algorithm) => $algorithm->getAlgorithmObject(), $this->id_token_signing_alg_values_supported));
        $checkers = [
            new AlgorithmChecker(array_map(static fn (JwtSigningAlgorithm $algorithm) => $algorithm->name, $this->id_token_signing_alg_values_supported))
        ];
        if ($this->enable_nonce) {
            $checkers[] = new NonceChecker(Session::get('oidc_nonce'));
        }
        $headerChecker = new HeaderCheckerManager($checkers, [new JWSTokenSupport()]);

        // We instantiate our JWS Verifier.
        $jwsVerifier = new JWSVerifier(
            $algorithmManager
        );

        // The serializer manager. We only use the JWS Compact Serialization Mode.
        $serializerManager = new JWSSerializerManager([
            new CompactSerializer(),
        ]);
        return new JWSLoader(
            $serializerManager,
            $jwsVerifier,
            $headerChecker
        );
    }

    /**
     * Gets the JWKs from the JWKS endpoint (if set) or from the JWKs property (if set)
     */
    private function getJWKs(): JWKSet
    {
        if ($this->jwks_endpoint && empty($this->jwks)) {
            $set = $this->client()->get($this->jwks_endpoint)->json();
            $this->jwks = JWKSet::createFromKeyData($set);
        }

        return $this->jwks;
    }
}
