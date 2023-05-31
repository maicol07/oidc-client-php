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

namespace Maicol07\OpenIDConnect;

use Jose\Component\Core\Algorithm;

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
    public function getAlgorithmObject(): Algorithm
    {
        $class = 'Jose\Component\Signature\Algorithm\\' . $this->name;
        return new $class();
    }

    /** @noinspection ReturnTernaryReplacementInspection */
    public static function tryFromName(string $name): ?self
    {
        return defined("self::$name") ? self::fromName($name) : null;
    }
    public static function fromName(string $name): self
    {
        return constant("self::$name");
    }
}
