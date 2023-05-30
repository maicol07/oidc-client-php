<?php

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
