<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Tests;

use Componenta\Auth\Session\Http\SessionCookieTransport;
use Componenta\Auth\Session\Http\SessionCredentialPayload;
use Componenta\Auth\Session\SessionCredential;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class SessionCookieTransportTest extends TestCase
{
    public function testStoresOnlySecureNonPersistentHostCookie(): void
    {
        $transport = new SessionCookieTransport();
        $credential = SessionCredential::fromBytes(str_repeat('a', 32));
        $response = $transport->store(
            new ServerRequest('GET', '/'),
            new Response(),
            new SessionCredentialPayload($credential),
        );
        $cookie = $response->getHeaderLine('Set-Cookie');

        self::assertStringContainsString('__Host-auth_session=', $cookie);
        self::assertStringContainsString('Path=/', $cookie);
        self::assertStringContainsString('SameSite=Lax', $cookie);
        self::assertStringContainsString('Secure', $cookie);
        self::assertStringContainsString('HttpOnly', $cookie);
        self::assertStringNotContainsString('Domain=', $cookie);
        self::assertStringNotContainsString('Max-Age=', $cookie);
        self::assertStringNotContainsString('Expires=', $cookie);
    }

    public function testRoundTripsCredential(): void
    {
        $transport = new SessionCookieTransport();
        $credential = SessionCredential::fromBytes(str_repeat('b', 32));
        $payload = $transport->extract(
            (new ServerRequest('GET', '/'))->withCookieParams([
                '__Host-auth_session' => $credential->toString(),
            ]),
        );

        self::assertInstanceOf(SessionCredentialPayload::class, $payload);
        self::assertSame(
            $credential->toString(),
            $payload->credential->toString(),
        );
    }
}
