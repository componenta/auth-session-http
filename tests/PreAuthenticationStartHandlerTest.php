<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Tests;

use Componenta\Auth\Session\Http\PreAuthenticationCookieTransport;
use Componenta\Auth\Session\Http\PreAuthenticationGrantPublisher;
use Componenta\Auth\Session\Http\PreAuthenticationStartHandler;
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
use Psr\Http\Message\ResponseFactoryInterface;

final class PreAuthenticationStartHandlerTest extends TestCase
{
    public function testStartsBrowserBoundTransactionAndPublishesNoStoreSecrets(): void
    {
        $grant = self::grant();
        $manager = new StartManagerFixture($grant);
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturn(new Response(204));

        $response = (new PreAuthenticationStartHandler(
            $manager,
            new PreAuthenticationGrantPublisher(
                new PreAuthenticationCookieTransport(),
            ),
            $responses,
            600,
        ))->handle(new ServerRequest('POST', '/auth/pre-auth'));

        self::assertSame(600, $manager->ttl);
        self::assertSame(204, $response->getStatusCode());
        self::assertStringContainsString(
            '__Host-auth_pre=',
            $response->getHeaderLine('Set-Cookie'),
        );
        self::assertSame(
            $grant->requestToken->toString(),
            $response->getHeaderLine('X-Pre-Auth-Token'),
        );
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame('no-cache', $response->getHeaderLine('Pragma'));
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
                $created->modify('+10 minutes'),
            ),
            PreAuthenticationCredential::fromBytes(str_repeat('a', 32)),
            PreAuthenticationRequestToken::fromBytes(str_repeat('b', 32)),
        );
    }
}

final class StartManagerFixture implements PreAuthenticationManagerInterface
{
    public ?int $ttl = null;

    public function __construct(private PreAuthenticationGrant $grant) {}

    public function create(int $ttlSeconds = 300): PreAuthenticationGrant
    {
        $this->ttl = $ttlSeconds;

        return $this->grant;
    }

    public function verify(
        PreAuthenticationCredential $credential,
        PreAuthenticationRequestToken $requestToken,
    ): ?PreAuthenticationTransaction {
        return null;
    }

    public function consume(
        PreAuthenticationCredential $credential,
        PreAuthenticationRequestToken $requestToken,
    ): ?PreAuthenticationTransaction {
        return null;
    }
}
