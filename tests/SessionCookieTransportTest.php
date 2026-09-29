<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Tests;

use Componenta\Auth\Http\Exception\InvalidPayloadException;
use Componenta\Auth\Http\Exception\TransportException;
use Componenta\Auth\Session\Http\SessionCookieTransport;
use Componenta\Auth\Session\Http\SessionCredentialPayload;
use Componenta\Auth\Session\SessionCredential;
use InvalidArgumentException;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use stdClass;

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

        self::assertStringStartsWith('__Host-auth_session=', $cookie);
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

    public function testMissingCookieReturnsNull(): void
    {
        self::assertNull(
            (new SessionCookieTransport())->extract(new ServerRequest('GET', '/')),
        );
    }

    #[DataProvider('invalidCookieValues')]
    public function testMalformedCookieValueIsRejected(mixed $value): void
    {
        $this->expectException(InvalidPayloadException::class);

        (new SessionCookieTransport())->extract(
            (new ServerRequest('GET', '/'))->withCookieParams([
                '__Host-auth_session' => $value,
            ]),
        );
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function invalidCookieValues(): iterable
    {
        yield 'empty' => [''];
        yield 'non-string' => [123];
        yield 'malformed credential' => ['not-a-session-credential'];
    }

    public function testUnsupportedStorePayloadIsRejected(): void
    {
        $this->expectException(TransportException::class);

        (new SessionCookieTransport())->store(
            new ServerRequest('GET', '/'),
            new Response(),
            new stdClass(),
        );
    }

    #[DataProvider('validSameSiteValues')]
    public function testSameSiteValuesAreNormalized(string $input, string $expected): void
    {
        $transport = new SessionCookieTransport(sameSite: $input);
        $credential = SessionCredential::fromBytes(str_repeat('c', 32));

        $response = $transport->store(
            new ServerRequest('GET', '/'),
            new Response(),
            new SessionCredentialPayload($credential),
        );

        self::assertSame($expected, $transport->sameSite);
        self::assertStringContainsString('SameSite=' . $expected, $response->getHeaderLine('Set-Cookie'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function validSameSiteValues(): iterable
    {
        yield 'lax' => ['lAx', 'Lax'];
        yield 'strict' => ['STRICT', 'Strict'];
        yield 'none' => ['NoNe', 'None'];
    }

    #[DataProvider('invalidConfigurations')]
    public function testInvalidConfigurationIsRejected(string $name, string $sameSite): void
    {
        $this->expectException(InvalidArgumentException::class);

        new SessionCookieTransport(name: $name, sameSite: $sameSite);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function invalidConfigurations(): iterable
    {
        yield 'missing Host prefix' => ['auth_session', 'Lax'];
        yield 'invalid cookie token' => ["__Host-bad\r\nname", 'Lax'];
        yield 'invalid SameSite' => ['__Host-auth_session', 'invalid'];
    }

    public function testRemovePublishesExpiredHostOnlyCookie(): void
    {
        $response = (new SessionCookieTransport())->remove(
            new ServerRequest('POST', '/logout'),
            new Response(),
        );

        $cookie = $response->getHeaderLine('Set-Cookie');

        self::assertStringStartsWith('__Host-auth_session=', $cookie);
        self::assertStringContainsString('Path=/', $cookie);
        self::assertStringContainsString('SameSite=Lax', $cookie);
        self::assertStringContainsString('Secure', $cookie);
        self::assertStringContainsString('HttpOnly', $cookie);
        self::assertStringContainsString('Expires=Thu, 01 Jan 1970 00:00:00 GMT', $cookie);
        self::assertStringContainsString('Max-Age=0', $cookie);
        self::assertStringNotContainsString('Domain=', $cookie);
    }

    public function testStoreReplacesOwnCookieAndPreservesUnrelatedCookies(): void
    {
        $transport = new SessionCookieTransport();
        $credential = SessionCredential::fromBytes(str_repeat('d', 32));
        $response = new Response(headers: [
            'Set-Cookie' => [
                '__Host-auth_session=old; Path=/; Secure; HttpOnly',
                'other=value; Path=/',
            ],
        ]);

        $updated = $transport->store(
            new ServerRequest('GET', '/'),
            $response,
            new SessionCredentialPayload($credential),
        );

        $cookies = $updated->getHeader('Set-Cookie');

        self::assertCount(2, $cookies);
        self::assertContains('other=value; Path=/', $cookies);
        self::assertSame(
            1,
            count(array_filter(
                $cookies,
                static fn(string $cookie): bool => str_starts_with($cookie, '__Host-auth_session='),
            )),
        );
        self::assertStringContainsString(rawurlencode($credential->toString()), implode("\n", $cookies));
    }

    public function testRemoveReplacesOwnCookieAndPreservesUnrelatedCookies(): void
    {
        $transport = new SessionCookieTransport();
        $response = new Response(headers: [
            'Set-Cookie' => [
                '__Host-auth_session=old; Path=/; Secure; HttpOnly',
                'other=value; Path=/',
            ],
        ]);

        $updated = $transport->remove(new ServerRequest('POST', '/logout'), $response);
        $cookies = $updated->getHeader('Set-Cookie');

        self::assertCount(2, $cookies);
        self::assertContains('other=value; Path=/', $cookies);
        self::assertSame(
            1,
            count(array_filter(
                $cookies,
                static fn(string $cookie): bool => str_starts_with($cookie, '__Host-auth_session='),
            )),
        );
        self::assertStringContainsString('Max-Age=0', implode("\n", $cookies));
    }
}
