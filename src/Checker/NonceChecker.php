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

namespace Maicol07\OpenIDConnect\Checker;

use Jose\Component\Checker\HeaderChecker;
use Jose\Component\Checker\InvalidHeaderException;

class NonceChecker implements HeaderChecker
{
    public function __construct(
        public readonly string $expectedNonce
    ) {}

    /**
     * @inheritDoc
     * @throws InvalidHeaderException
     */
    public function checkHeader(mixed $value): void
    {
        if ($value !== $this->expectedNonce) {
            throw new InvalidHeaderException('Invalid header "nonce".', 'nonce', $value);
        }
    }

    /**
     * @inheritDoc
     */
    public function supportedHeader(): string
    {
        return 'nonce';
    }

    /**
     * @inheritDoc
     */
    public function protectedHeaderOnly(): bool
    {
        return true;
    }
}
