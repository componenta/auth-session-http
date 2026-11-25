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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

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
        self::assertSame($grant->transaction, $manager->verify($grant->credential, $grant->requestToken));
    }

    /** @return iterable<string, array{string}> */
    public static function publicationFailures(): iterable
    {
        yield 'response factory' => ['factory'];
        yield 'cookie header' => ['cookie'];
        yield 'request token header' => ['X-Pre-Auth-Token'];
        yield 'cache header' => ['Cache-Control'];
    }

    #[DataProvider('publicationFailures')]
    public function testFailedPublicationConsumesTheUnpublishedTransaction(string $failedStage): void
    {
        $grant = self::grant();
        $manager = new StartManagerFixture($grant);
        $failure = new \RuntimeException('Response publication failed.');
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getHeader')->willReturn([]);
        $response->method('withoutHeader')->willReturn($response);
        $response->method('withAddedHeader')->willReturnCallback(
            static function (string $name, mixed $value) use ($failedStage, $failure, $response): ResponseInterface {
                if ($failedStage === 'cookie') throw $failure;

                return $response;
            },
        );
        $response->method('withHeader')->willReturnCallback(
            static function (string $name, mixed $value) use ($failedStage, $failure, $response): ResponseInterface {
                if ($name === $failedStage) throw $failure;

                return $response;
            },
        );
        $responses = $this->createStub(ResponseFactoryInterface::class);
        if ($failedStage === 'factory') {
            $responses->method('createResponse')->willThrowException($failure);
        } else {
            $responses->method('createResponse')->willReturn($response);
        }

        try {
            (new PreAuthenticationStartHandler(
                $manager,
                new PreAuthenticationGrantPublisher(new PreAuthenticationCookieTransport()),
                $responses,
            ))->handle(new ServerRequest('POST', '/auth/pre-auth'));
            self::fail('Publication failure must propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertNull($manager->verify($grant->credential, $grant->requestToken));
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
    private bool $active = false;

    public function __construct(private PreAuthenticationGrant $grant) {}

    public function create(int $ttlSeconds = 300): PreAuthenticationGrant
    {
        $this->ttl = $ttlSeconds;
        $this->active = true;

        return $this->grant;
    }

    public function verify(
        PreAuthenticationCredential $credential,
        PreAuthenticationRequestToken $requestToken,
    ): ?PreAuthenticationTransaction {
        return $this->active
            && $credential->toString() === $this->grant->credential->toString()
            && $requestToken->toString() === $this->grant->requestToken->toString()
            ? $this->grant->transaction
            : null;
    }

    public function consume(
        PreAuthenticationCredential $credential,
        PreAuthenticationRequestToken $requestToken,
    ): ?PreAuthenticationTransaction {
        $transaction = $this->verify($credential, $requestToken);
        if ($transaction !== null) $this->active = false;

        return $transaction;
    }
}
