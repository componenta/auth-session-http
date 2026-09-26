<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http;

use Componenta\Auth\Session\SessionCredential;

final readonly class SessionCredentialPayload implements \JsonSerializable
{
    public function __construct(
        #[\SensitiveParameter]
        public SessionCredential $credential,
    ) {}

    /** @return array{credential: string} */
    public function __debugInfo(): array
    {
        return ['credential' => '[REDACTED]'];
    }

    /** @return array{credential: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
