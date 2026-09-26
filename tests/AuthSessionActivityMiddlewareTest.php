<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionGrant;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\AuthSessionPolicy;
use Componenta\Auth\Session\Http\AuthSessionActivityMiddleware;
use Componenta\Auth\Session\Http\SessionActivity;
use Componenta\Auth\Session\RevocationReason;
use Componenta\Auth\Session\RotationReason;
use Componenta\Auth\Session\SessionCredential;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class AuthSessionActivityMiddlewareTest extends TestCase
{
    public function testOnlyExplicitInteractiveRequestTouchesSession(): void
    {
        $session = self::session();
        $manager = new ActivityManagerFixture();
        $middleware = new AuthSessionActivityMiddleware($manager);

        $middleware->process(
            (new ServerRequest('GET', '/background'))
                ->withAttribute(AuthSession::class, $session),
            new ActivityResponseHandlerFixture(200),
        );
        self::assertSame(0, $manager->touches);

        $middleware->process(
            (new ServerRequest('GET', '/interactive'))
                ->withAttribute(AuthSession::class, $session)
                ->withAttribute(
                    SessionActivity::class,
                    SessionActivity::Interactive,
                ),
            new ActivityResponseHandlerFixture(200),
        );
        self::assertSame(1, $manager->touches);
    }

    public function testDeniedInteractiveRequestDoesNotTouchSession(): void
    {
        $session = self::session();
        $manager = new ActivityManagerFixture();
        $middleware = new AuthSessionActivityMiddleware($manager);
        $request = (new ServerRequest('POST', '/unsafe'))
            ->withAttribute(AuthSession::class, $session)
            ->withAttribute(
                SessionActivity::class,
                SessionActivity::Interactive,
            );

        $middleware->process(
            $request,
            new ActivityResponseHandlerFixture(403),
        );
        $middleware->process(
            $request,
            new ActivityResponseHandlerFixture(401),
        );

        self::assertSame(0, $manager->touches);
    }

    private static function session(): AuthSession
    {
        $now = new DateTimeImmutable('2030-01-01T00:00:00+00:00');

        return new AuthSession(
            uuid: Uuid::fromString(
                '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
            ),
            subjectId: Uuid::fromString(
                '018f6d5d-3f7a-7a9b-8c2f-123456789abd',
            ),
            evidence: new AuthenticationEvidence(['session']),
            credentialGeneration: 1,
            createdAt: $now,
            authenticatedAt: $now,
            reauthenticatedAt: null,
            lastActiveAt: $now,
            idleExpiresAt: $now->modify('+30 minutes'),
            absoluteExpiresAt: $now->modify('+8 hours'),
        );
    }
}

final class ActivityManagerFixture implements AuthSessionManagerInterface
{
    public int $touches = 0;

    public function create(
        UuidInterface $subjectId,
        AuthenticationEvidence $evidence,
        AuthSessionPolicy $policy,
        array $metadata = [],
    ): AuthSessionGrant {
        throw new \LogicException('Not used.');
    }

    public function resume(SessionCredential $credential): ?AuthSession
    {
        return null;
    }

    public function touch(AuthSession $observed): void
    {
        ++$this->touches;
    }

    public function rotate(
        AuthSession $observed,
        AuthenticationEvidence $evidence,
        RotationReason $reason,
        ?AuthSessionPolicy $policy = null,
    ): AuthSessionGrant {
        throw new \LogicException('Not used.');
    }

    public function revoke(
        UuidInterface $sessionId,
        RevocationReason $reason,
    ): void {}

    public function revokePresentedCredential(
        SessionCredential $credential,
        RevocationReason $reason,
    ): void {}

    public function revokeAll(
        UuidInterface $subjectId,
        ?UuidInterface $exceptSessionId = null,
        RevocationReason $reason = RevocationReason::UserRequested,
    ): void {}

    public function isGrantCurrent(AuthSessionGrant $grant): bool
    {
        return false;
    }
}

final readonly class ActivityResponseHandlerFixture implements
    RequestHandlerInterface
{
    public function __construct(private int $status) {}

    public function handle(
        ServerRequestInterface $request,
    ): ResponseInterface {
        return new Response($this->status);
    }
}
