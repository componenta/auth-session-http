<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Context;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionGrant;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\AuthSessionPolicy;
use Componenta\Auth\Session\Http\SessionAuthenticationStrategy;
use Componenta\Auth\Session\Http\SessionCredentialPayload;
use Componenta\Auth\Session\RevocationReason;
use Componenta\Auth\Session\RotationReason;
use Componenta\Auth\Session\SessionCredential;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class SessionAuthenticationStrategyTest extends TestCase
{
    public function testResumesSessionAndReturnsItAsTypedState(): void
    {
        $identity = new StrategyIdentityFixture();
        $session = self::session($identity->uuid);
        $manager = new StrategyManagerFixture($session);
        $provider = new StrategyIdentityProviderFixture($identity);
        $strategy = new SessionAuthenticationStrategy($manager, $provider);

        $result = $strategy->attempt(
            new SessionCredentialPayload(
                SessionCredential::fromBytes(str_repeat('a', 32)),
            ),
            new Context(),
        );

        self::assertSame($identity, $result->subject);
        self::assertSame($session, $result->state);
        self::assertSame($session->evidence, $result->evidence);
    }

    public function testUnknownCredentialIsSoftFailure(): void
    {
        $strategy = new SessionAuthenticationStrategy(
            new StrategyManagerFixture(null),
            new StrategyIdentityProviderFixture(null),
        );
        $result = $strategy->attempt(
            new SessionCredentialPayload(
                SessionCredential::fromBytes(str_repeat('a', 32)),
            ),
            new Context(),
        );

        self::assertInstanceOf(InvalidCredentials::class, $result->subject);
        self::assertTrue($result->continueOnFailure);
    }

    private static function session(UuidInterface $subjectId): AuthSession
    {
        $now = new DateTimeImmutable('2030-01-01T00:00:00+00:00');

        return new AuthSession(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
            $subjectId,
            new AuthenticationEvidence(['session']),
            1,
            $now,
            $now,
            null,
            $now,
            $now->modify('+30 minutes'),
            $now->modify('+8 hours'),
        );
    }
}

final class StrategyIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abd');
    }
}

final readonly class StrategyIdentityProviderFixture implements IdentityProviderInterface
{
    public function __construct(private ?IdentityInterface $identity) {}
    public function findByUuid(UuidInterface $uuid): ?IdentityInterface { return $this->identity; }
}

final class StrategyManagerFixture implements AuthSessionManagerInterface
{
    public function __construct(private ?AuthSession $session) {}
    public function create(UuidInterface $subjectId, AuthenticationEvidence $evidence, AuthSessionPolicy $policy, array $metadata = []): AuthSessionGrant { throw new \LogicException(); }
    public function resume(SessionCredential $credential): ?AuthSession { return $this->session; }
    public function touch(AuthSession $observed): void {}
    public function rotate(AuthSession $observed, AuthenticationEvidence $evidence, RotationReason $reason, ?AuthSessionPolicy $policy = null): AuthSessionGrant { throw new \LogicException(); }
    public function revoke(UuidInterface $sessionId, RevocationReason $reason): void {}
    public function revokePresentedCredential(SessionCredential $credential, RevocationReason $reason): void {}
    public function revokeAll(UuidInterface $subjectId, ?UuidInterface $exceptSessionId = null): void {}
    public function isGrantCurrent(AuthSessionGrant $grant): bool { return false; }
}
