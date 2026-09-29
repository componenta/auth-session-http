<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Tests;

use Componenta\Auth\AuthenticationAdmission;
use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationGuardInterface;
use Componenta\Auth\Denied\DeniedReason;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Session\AssuranceRequirement;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionRegistryInterface;
use Componenta\Auth\Session\Http\Csrf\AuthSessionCsrfTokenManager;
use Componenta\Auth\Session\Http\FactorManagementGuard;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use InvalidArgumentException;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class FactorManagementGuardTest extends TestCase
{
    #[DataProvider('requests')]
    public function testAuthoritativeSessionFreshnessAdmissionAndCsrf(string $case, ?int $status): void
    {
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $uuid = new UuidFactory();
        $subject = $uuid->generate();
        $identity = new readonly class($subject) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
        $now = $clock->now();
        $observed = $this->session($uuid->generate(), $subject, $now->modify('-60 seconds'));
        $current = match ($case) {
            'revoked' => null,
            'stale', 'forged-fresh-attribute' => $this->session($observed->uuid, $subject, $now->modify('-600 seconds')),
            'future' => $this->session($observed->uuid, $subject, $now->modify('+10 seconds')),
            'rotated' => $this->session($observed->uuid, $subject, $now->modify('-60 seconds'), 2),
            'remembered-only' => $this->session($observed->uuid, $subject, $now->modify('-60 seconds'), 1, 'remember_me'),
            'wrong-subject' => $this->session($observed->uuid, $uuid->generate(), $now->modify('-60 seconds')),
            default => $observed,
        };

        $registry = $this->createStub(AuthSessionRegistryInterface::class);
        $registry->method('find')->willReturn($current);
        $identities = $this->createStub(IdentityProviderInterface::class);
        $identities->method('findByUuid')->willReturn($identity);
        $admissionGuard = $this->createStub(AuthenticationGuardInterface::class);
        $admissionGuard->method('check')->willReturn($case === 'disabled' ? new DeniedReason('user_disabled') : null);

        $key = str_repeat('k', 32);
        $guard = new FactorManagementGuard(
            $registry,
            new AuthenticationAdmission($identities, $admissionGuard),
            new AssuranceRequirement(requiredMethods: ['password'], maxAge: 300),
            $clock,
            new Psr17Factory(),
            $key,
        );

        $request = (new ServerRequest($case === 'get' ? 'GET' : 'POST', 'https://example.test/factors'))
            ->withAttribute(IdentityInterface::class, $identity)
            ->withAttribute(AuthSession::class, $observed)
            ->withHeader('Origin', 'https://example.test')
            ->withHeader('X-CSRF-Token', (new AuthSessionCsrfTokenManager($observed, $key))->generate());

        if ($case === 'no-csrf') {
            $request = $request->withoutHeader('X-CSRF-Token');
        }

        if ($case === 'foreign-origin') {
            $request = $request->withHeader('Origin', 'https://attacker.test');
        }

        if ($case === 'missing-origin') {
            $request = $request->withoutHeader('Origin');
        }

        if ($case === 'no-session') {
            $request = $request->withoutAttribute(AuthSession::class);
        }

        if ($case === 'no-identity') {
            $request = $request->withoutAttribute(IdentityInterface::class);
        }

        $result = $guard->check($request);

        self::assertSame($status, $result?->getStatusCode());

        if ($result !== null) {
            self::assertStringContainsString('no-store', $result->getHeaderLine('Cache-Control'));
        }
    }

    /**
     * @return iterable<string, array{string, ?int}>
     */
    public static function requests(): iterable
    {
        yield 'allowed' => ['allowed', null];

        foreach (['stale', 'future', 'forged-fresh-attribute', 'remembered-only', 'no-csrf', 'foreign-origin', 'missing-origin', 'disabled'] as $case) {
            yield $case => [$case, 403];
        }

        foreach (['revoked', 'rotated', 'wrong-subject', 'no-session', 'no-identity'] as $case) {
            yield $case => [$case, 401];
        }

        yield 'get' => ['get', 405];
    }

    #[DataProvider('invalidAssuranceRequirements')]
    public function testUnboundedOrUnspecifiedAssuranceIsNotAccepted(AssuranceRequirement $requirement): void
    {
        $registry = $this->createStub(AuthSessionRegistryInterface::class);
        $admission = new AuthenticationAdmission(
            $this->createStub(IdentityProviderInterface::class),
            $this->createStub(AuthenticationGuardInterface::class),
        );

        $this->expectException(InvalidArgumentException::class);

        new FactorManagementGuard(
            $registry,
            $admission,
            $requirement,
            new FrozenClock(1000, 'UTC'),
            new Psr17Factory(),
            str_repeat('k', 32),
        );
    }

    /**
     * @return iterable<string, array{AssuranceRequirement}>
     */
    public static function invalidAssuranceRequirements(): iterable
    {
        yield 'unbounded' => [new AssuranceRequirement()];
        yield 'missing methods' => [new AssuranceRequirement(maxAge: 300)];
        yield 'exceeds freshness limit' => [new AssuranceRequirement(['password'], maxAge: 601)];
    }

    private function session(
        UuidInterface $id,
        UuidInterface $subject,
        \DateTimeImmutable $at,
        int $generation = 1,
        string $method = 'password',
    ): AuthSession {
        return new AuthSession(
            $id,
            $subject,
            new AuthenticationEvidence([$method]),
            $generation,
            $at,
            null,
            $at,
            $at->modify('+1 hour'),
            $at->modify('+8 hours'),
        );
    }
}
