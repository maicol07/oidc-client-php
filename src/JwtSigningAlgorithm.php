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

namespace Maicol07\OpenIDConnect;

use Lcobucci\JWT\Signer;

enum JwtSigningAlgorithm
{
    case HS256;
    case HS384;
    case HS512;
    case RS256;
    case RS384;
    case RS512;
    case ES256;
    case ES384;
    case ES512;
    case EdDSA;
    case BLAKE2B;

    public function getSigner(): Signer
    {
        return match ($this) {
            self::HS256 => new Signer\Hmac\Sha256(),
            self::HS384 => new Signer\Hmac\Sha384(),
            self::HS512 => new Signer\Hmac\Sha512(),
            self::BLAKE2B => new Signer\Blake2b(),
            self::RS256 => new Signer\Rsa\Sha256(),
            self::RS384 => new Signer\Rsa\Sha384(),
            self::RS512 => new Signer\Rsa\Sha512(),
            self::ES256 => Signer\Ecdsa\Sha256::create(),
            self::ES384 => Signer\Ecdsa\Sha384::create(),
            self::ES512 => Signer\Ecdsa\Sha512::create(),
            self::EdDSA => new Signer\Eddsa()
        };
    }

    public static function fromName(string $name): JwtSigningAlgorithm {
        return constant("self::$name");
    }
}
