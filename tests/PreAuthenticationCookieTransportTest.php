<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Tests;

use Componenta\Auth\Http\Exception\InvalidPayloadException;
use Componenta\Auth\Session\Http\PreAuthenticationCookieTransport;
use Componenta\Auth\Session\PreAuthenticationCredential;
use InvalidArgumentException;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PreAuthenticationCookieTransportTest extends TestCase
{
    public function testStoresSecureNonPersistentHostCookie(): void
    {
        $transport = new PreAuthenticationCookieTransport();
        $credential = PreAuthenticationCredential::fromBytes(str_repeat('a', 32));

        $response = $transport->store(new Response(), $credential);
        $cookie = $response->getHeaderLine('Set-Cookie');

        self::assertStringStartsWith('__Host-auth_pre=', $cookie);
        self::assertStringContainsString(rawurlencode($credential->toString()), $cookie);
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
        $transport = new PreAuthenticationCookieTransport();
        $credential = PreAuthenticationCredential::fromBytes(str_repeat('b', 32));

        $extracted = $transport->extract(
            (new ServerRequest('POST', '/verify'))->withCookieParams([
                '__Host-auth_pre' => $credential->toString(),
            ]),
        );

        self::assertNotNull($extracted);
        self::assertSame($credential->toString(), $extracted->toString());
    }

    public function testMissingCookieReturnsNull(): void
    {
        self::assertNull(
            (new PreAuthenticationCookieTransport())->extract(
                new ServerRequest('POST', '/verify'),
            ),
        );
    }

    #[DataProvider('invalidCookieValues')]
    public function testMalformedCookieValueIsRejected(mixed $value): void
    {
        $this->expectException(InvalidPayloadException::class);

        (new PreAuthenticationCookieTransport())->extract(
            (new ServerRequest('POST', '/verify'))->withCookieParams([
                '__Host-auth_pre' => $value,
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
        yield 'malformed credential' => ['not-a-pre-auth-credential'];
    }

    #[DataProvider('validSameSiteValues')]
    public function testSameSiteValuesAreNormalized(string $input, string $expected): void
    {
        $transport = new PreAuthenticationCookieTransport(sameSite: $input);
        $credential = PreAuthenticationCredential::fromBytes(str_repeat('c', 32));

        $response = $transport->store(new Response(), $credential);

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

        new PreAuthenticationCookieTransport(name: $name, sameSite: $sameSite);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function invalidConfigurations(): iterable
    {
        yield 'missing Host prefix' => ['auth_pre', 'Lax'];
        yield 'invalid cookie token' => ["__Host-bad\r\nname", 'Lax'];
        yield 'invalid SameSite' => ['__Host-auth_pre', 'invalid'];
    }

    public function testRemovePublishesExpiredHostOnlyCookie(): void
    {
        $response = (new PreAuthenticationCookieTransport())->remove(new Response());
        $cookie = $response->getHeaderLine('Set-Cookie');

        self::assertStringStartsWith('__Host-auth_pre=', $cookie);
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
        $transport = new PreAuthenticationCookieTransport();
        $credential = PreAuthenticationCredential::fromBytes(str_repeat('d', 32));
        $response = new Response(headers: [
            'Set-Cookie' => [
                '__Host-auth_pre=old; Path=/; Secure; HttpOnly',
                'other=value; Path=/',
            ],
        ]);

        $updated = $transport->store($response, $credential);
        $cookies = $updated->getHeader('Set-Cookie');

        self::assertCount(2, $cookies);
        self::assertContains('other=value; Path=/', $cookies);
        self::assertSame(
            1,
            count(array_filter(
                $cookies,
                static fn(string $cookie): bool => str_starts_with($cookie, '__Host-auth_pre='),
            )),
        );
        self::assertStringContainsString(rawurlencode($credential->toString()), implode("\n", $cookies));
    }

    public function testRemoveReplacesOwnCookieAndPreservesUnrelatedCookies(): void
    {
        $transport = new PreAuthenticationCookieTransport();
        $response = new Response(headers: [
            'Set-Cookie' => [
                '__Host-auth_pre=old; Path=/; Secure; HttpOnly',
                'other=value; Path=/',
            ],
        ]);

        $updated = $transport->remove($response);
        $cookies = $updated->getHeader('Set-Cookie');

        self::assertCount(2, $cookies);
        self::assertContains('other=value; Path=/', $cookies);
        self::assertSame(
            1,
            count(array_filter(
                $cookies,
                static fn(string $cookie): bool => str_starts_with($cookie, '__Host-auth_pre='),
            )),
        );
        self::assertStringContainsString('Max-Age=0', implode("\n", $cookies));
    }
}
