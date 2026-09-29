<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Tests\Csrf;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\Http\Csrf\AuthSessionCsrfMiddleware;
use Componenta\Auth\Session\Http\Csrf\AuthSessionCsrfTokenManager;
use Nyholm\Psr7\Factory\Psr17Factory;
use Componenta\Identity\Uuid;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class AuthSessionCsrfTokenManagerTest extends TestCase
{
    public function testTokenIsStableForGenerationAndChangesAfterRotation(): void
    {
        $key = str_repeat('k', 32);
        $first = new AuthSessionCsrfTokenManager(self::session(1), $key);
        $second = new AuthSessionCsrfTokenManager(self::session(2), $key);
        $token = $first->generate();

        self::assertSame($token, $first->getActive());
        self::assertTrue($first->validate($token));
        self::assertFalse($second->validate($token));
        self::assertNotSame($token, $second->generate());
    }

    public function testTokenDoesNotContainSessionUuid(): void
    {
        $session = self::session(1);
        $token = (new AuthSessionCsrfTokenManager(
            $session,
            str_repeat('k', 32),
        ))->generate();

        self::assertStringNotContainsString(
            $session->uuid->toString(),
            $token,
        );
    }

    public function testDebugOutputRedactsKeyAndSessionIdentity(): void
    {
        $session = self::session(1);
        $key = str_repeat('secret-key-', 4);
        $manager = new AuthSessionCsrfTokenManager($session, $key);
        $middleware = new AuthSessionCsrfMiddleware(new Psr17Factory(), $key);

        $managerDebug = print_r($manager, true);
        self::assertStringNotContainsString($key, $managerDebug);
        self::assertStringNotContainsString($session->uuid->toString(), $managerDebug);

        $middlewareDebug = print_r($middleware, true);
        self::assertStringNotContainsString($key, $middlewareDebug);
    }

    private static function session(int $generation): AuthSession
    {
        $now = new DateTimeImmutable('2030-01-01T00:00:00+00:00');

        return new AuthSession(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abd'),
            new AuthenticationEvidence(['session']),
            $generation,
            $now,
            null,
            $now,
            $now->modify('+30 minutes'),
            $now->modify('+8 hours'),
        );
    }
}
