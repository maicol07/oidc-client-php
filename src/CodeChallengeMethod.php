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
/** @noinspection ContractViolationInspection */

namespace Maicol07\OpenIDConnect;

enum CodeChallengeMethod: string
{
    case PLAIN = 'plain';
    case S256 = 'S256';

    public function algorithm(): string {
        return match ($this) {
            self::S256 => 'sha256',
            self::PLAIN => '',
        };
    }
}
