<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\Http\Csrf\AuthSessionCsrfMiddleware;
use Componenta\Auth\Session\Http\Csrf\AuthSessionCsrfTokenManager;
use Componenta\Identity\UuidFactory;
use DateTimeImmutable;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Server\RequestHandlerInterface;

final class AuthSessionCsrfConfigurationTest extends TestCase
{
    public function testTrustedOriginsDoNotFollowCallerReferences(): void
    {
        $origin = 'https://console.example.test';
        $key = str_repeat('k', 32);
        $middleware = new AuthSessionCsrfMiddleware(
            new Psr17Factory(),
            $key,
            trustedOrigins: [&$origin],
        );
        $origin = 'https://other.example.test';
        $session = self::session();
        $request = (new ServerRequest('POST', 'https://example.test/account'))
            ->withAttribute(AuthSession::class, $session)
            ->withHeader('Origin', 'https://console.example.test')
            ->withHeader('X-CSRF-Token', (new AuthSessionCsrfTokenManager($session, $key))->generate());
        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn(new Response(204));

        self::assertSame(403, $middleware->process(
            $request->withHeader('Origin', $origin),
            $handler,
        )->getStatusCode());
        self::assertSame(204, $middleware->process($request, $handler)->getStatusCode());
    }

    public function testExcludedPathsDoNotFollowCallerReferences(): void
    {
        $path = '/health';
        $middleware = new AuthSessionCsrfMiddleware(
            new Psr17Factory(),
            str_repeat('k', 32),
            excludedPaths: [&$path],
        );
        $path = '/account';
        $session = self::session();
        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn(new Response(204));

        self::assertSame(403, $middleware->process(
            (new ServerRequest('POST', 'https://example.test/account'))->withAttribute(AuthSession::class, $session),
            $handler,
        )->getStatusCode());
        self::assertSame(204, $middleware->process(
            (new ServerRequest('POST', 'https://example.test/health'))->withAttribute(AuthSession::class, $session),
            $handler,
        )->getStatusCode());
    }

    private static function session(): AuthSession
    {
        $now = new DateTimeImmutable('2030-01-01T00:00:00+00:00');
        $uuids = new UuidFactory();

        return new AuthSession(
            $uuids->generate(),
            $uuids->generate(),
            new AuthenticationEvidence(['password']),
            1,
            $now,
            null,
            $now,
            $now->modify('+1 hour'),
            $now->modify('+8 hours'),
        );
    }
}
