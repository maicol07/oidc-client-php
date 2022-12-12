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

namespace Maicol07\OpenIDConnect\Jwk;

use Illuminate\Support\Str;
use Jose\Component\Core\Util\ECKey;
use Jose\Component\Core\Util\RSAKey;
use Lcobucci\JWT\Signer\Key;
use Maicol07\OpenIDConnect\ClientException;

class Jwk implements Key
{
    public function __construct(
        private \Jose\Component\Core\JWK $jwk
    ) {}

    public function contents(): string
    {
        $algorithm_type = $this->getAlgorithmType();

        return match ($algorithm_type) {
            'RSA' => RSAKey::createFromJWK($this->jwk)->toPEM(),
            'EC' => ECKey::createFromJWK($this->jwk)->toPEM(),
            default => throw new ClientException("Unable to convert JWK to PEM. Unsupported algorithm type: $algorithm_type"),
        };
    }

    public function passphrase(): string
    {
        return '';
    }

    public function getAlgorithm(): string
    {
        return $this->jwk->get('alg');
    }

    public function getAlgorithmType(): string {
        return $this->jwk->get('kty');
    }
}
