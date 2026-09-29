<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Tests\Csrf;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\Http\Csrf\AuthSessionCsrfMiddleware;
use Componenta\Auth\Session\Http\Csrf\AuthSessionCsrfTokenManager;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use InvalidArgumentException;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\DataProvider;
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

    public function testTokenIsBoundToExactSessionUuid(): void
    {
        $key = str_repeat('k', 32);
        $first = new AuthSessionCsrfTokenManager(
            self::session(1, Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc')),
            $key,
        );
        $second = new AuthSessionCsrfTokenManager(
            self::session(1, Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abe')),
            $key,
        );

        $token = $first->generate();

        self::assertNotSame($token, $second->generate());
        self::assertFalse($second->validate($token));
    }

    public function testTokenIsBoundToServerKey(): void
    {
        $session = self::session(1);
        $first = new AuthSessionCsrfTokenManager($session, str_repeat('a', 32));
        $second = new AuthSessionCsrfTokenManager($session, str_repeat('b', 32));

        self::assertNotSame($first->generate(), $second->generate());
    }

    public function testTokenHasUnpaddedBase64UrlShape(): void
    {
        $token = (new AuthSessionCsrfTokenManager(
            self::session(1),
            str_repeat('k', 32),
        ))->generate();

        self::assertMatchesRegularExpression('/\A[A-Za-z0-9_-]{43}\z/D', $token);
        self::assertStringNotContainsString('=', $token);
        self::assertStringNotContainsString('+', $token);
        self::assertStringNotContainsString('/', $token);
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

    public function testEmptyTokenIsRejected(): void
    {
        $manager = new AuthSessionCsrfTokenManager(
            self::session(1),
            str_repeat('k', 32),
        );

        self::assertFalse($manager->validate(''));
    }

    #[DataProvider('invalidKeyLengths')]
    public function testInvalidKeyLengthIsRejected(int $length): void
    {
        $this->expectException(InvalidArgumentException::class);

        new AuthSessionCsrfTokenManager(self::session(1), str_repeat('k', $length));
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function invalidKeyLengths(): iterable
    {
        yield 'below minimum' => [31];
        yield 'above maximum' => [4097];
    }

    #[DataProvider('validKeyLengths')]
    public function testBoundaryKeyLengthIsAccepted(int $length): void
    {
        $manager = new AuthSessionCsrfTokenManager(
            self::session(1),
            str_repeat('k', $length),
        );

        self::assertTrue($manager->validate($manager->generate()));
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function validKeyLengths(): iterable
    {
        yield 'minimum' => [32];
        yield 'maximum' => [4096];
    }

    public function testDebugOutputRedactsKeyAndSessionIdentity(): void
    {
        $session = self::session(1);
        $key = str_repeat('secret-key-', 4);
        $manager = new AuthSessionCsrfTokenManager($session, $key);
        $middleware = new AuthSessionCsrfMiddleware(new Psr17Factory(), $key);

        self::assertSame(
            ['session' => '[REDACTED]', 'key' => '[REDACTED]'],
            $manager->__debugInfo(),
        );
        self::assertSame(
            ['key' => '[REDACTED]'],
            $middleware->__debugInfo(),
        );

        $managerDebug = print_r($manager, true);
        self::assertStringNotContainsString($key, $managerDebug);
        self::assertStringNotContainsString($session->uuid->toString(), $managerDebug);

        $middlewareDebug = print_r($middleware, true);
        self::assertStringNotContainsString($key, $middlewareDebug);
    }

    private static function session(
        int $generation,
        ?UuidInterface $uuid = null,
    ): AuthSession {
        $now = new DateTimeImmutable('2030-01-01T00:00:00+00:00');

        return new AuthSession(
            $uuid ?? Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
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
