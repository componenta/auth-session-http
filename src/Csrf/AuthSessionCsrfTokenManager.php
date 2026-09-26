<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Csrf;

use Componenta\Auth\Session\AuthSession;
use Componenta\Http\Middleware\Csrf\CsrfTokenManagerInterface;

final readonly class AuthSessionCsrfTokenManager implements CsrfTokenManagerInterface
{
    private const int MIN_KEY_BYTES = 32;
    private const int MAX_KEY_BYTES = 4096;

    public function __construct(
        private AuthSession $session,
        #[\SensitiveParameter]
        private string $key,
    ) {
        $length = strlen($this->key);

        if ($length < self::MIN_KEY_BYTES || $length > self::MAX_KEY_BYTES) {
            throw new \InvalidArgumentException(
                'Auth-session CSRF key must contain between 32 and 4096 bytes.',
            );
        }
    }

    #[\Override]
    public function generate(): string
    {
        return $this->token();
    }

    #[\Override]
    public function validate(#[\SensitiveParameter] string $token): bool
    {
        return $token !== '' && hash_equals($this->token(), $token);
    }

    #[\Override]
    public function getActive(): string
    {
        return $this->token();
    }

    private function token(): string
    {
        $mac = hash_hmac(
            'sha256',
            "componenta-auth-session-csrf-v1\0"
                . $this->session->uuid->toString()
                . "\0"
                . (string) $this->session->credentialGeneration,
            $this->key,
            true,
        );

        return rtrim(strtr(base64_encode($mac), '+/', '-_'), '=');
    }
}
