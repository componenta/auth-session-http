<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Tests;

use Componenta\Auth\Session\Http\PreAuthenticationConsumer;
use Componenta\Auth\Session\Http\PreAuthenticationCookieTransport;
use Componenta\Auth\Session\Http\PreAuthenticationGrantPublisher;
use Componenta\Auth\Session\PreAuthenticationCredential;
use Componenta\Auth\Session\PreAuthenticationGrant;
use Componenta\Auth\Session\PreAuthenticationManagerInterface;
use Componenta\Auth\Session\PreAuthenticationRequestToken;
use Componenta\Auth\Session\PreAuthenticationTransaction;
use Componenta\Identity\Uuid;
use DateTimeImmutable;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class PreAuthenticationHttpTest extends TestCase
{
    public function testPublisherSeparatesHttpOnlyCookieFromRequestToken(): void
    {
        $grant = self::grant();
        $response = (new PreAuthenticationGrantPublisher(
            new PreAuthenticationCookieTransport(),
        ))->publish(new Response(), $grant);

        $cookie = $response->getHeaderLine('Set-Cookie');

        self::assertStringContainsString('__Host-auth_pre=', $cookie);
        self::assertStringContainsString('HttpOnly', $cookie);
        self::assertStringContainsString('Secure', $cookie);
        self::assertStringNotContainsString(
            $grant->requestToken->toString(),
            $cookie,
        );
        self::assertSame(
            $grant->requestToken->toString(),
            $response->getHeaderLine('X-Pre-Auth-Token'),
        );
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }

    public function testConsumerRequiresBothBrowserSecrets(): void
    {
        $grant = self::grant();
        $manager = new PreAuthenticationManagerFixture($grant->transaction);
        $consumer = new PreAuthenticationConsumer(
            $manager,
            new PreAuthenticationCookieTransport(),
        );
        $request = (new ServerRequest('POST', '/verify'))
            ->withCookieParams([
                '__Host-auth_pre' => $grant->credential->toString(),
            ])
            ->withHeader(
                'X-Pre-Auth-Token',
                $grant->requestToken->toString(),
            );

        self::assertSame($grant->transaction, $consumer->consume($request));
        self::assertSame(
            $grant->credential->toString(),
            $manager->credential?->toString(),
        );
        self::assertSame(
            $grant->requestToken->toString(),
            $manager->requestToken?->toString(),
        );
    }

    private static function grant(): PreAuthenticationGrant
    {
        $created = new DateTimeImmutable('2030-01-01T00:00:00+00:00');

        return new PreAuthenticationGrant(
            new PreAuthenticationTransaction(
                Uuid::fromString(
                    '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
                ),
                $created,
                $created->modify('+5 minutes'),
            ),
            PreAuthenticationCredential::fromBytes(str_repeat('a', 32)),
            PreAuthenticationRequestToken::fromBytes(str_repeat('b', 32)),
        );
    }
}

final class PreAuthenticationManagerFixture implements
    PreAuthenticationManagerInterface
{
    public ?PreAuthenticationCredential $credential = null;
    public ?PreAuthenticationRequestToken $requestToken = null;

    public function __construct(
        private PreAuthenticationTransaction $transaction,
    ) {}

    public function create(int $ttlSeconds = 300): PreAuthenticationGrant
    {
        throw new \LogicException('Not used.');
    }

    public function consume(
        PreAuthenticationCredential $credential,
        PreAuthenticationRequestToken $requestToken,
    ): ?PreAuthenticationTransaction {
        $this->credential = $credential;
        $this->requestToken = $requestToken;

        return $this->transaction;
    }
}
