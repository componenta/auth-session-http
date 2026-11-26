<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\ReplacingPayloadStorage;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionGrant;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\Http\AuthSessionGrantPublisher;
use Componenta\Auth\Session\Http\SessionCookieTransport;
use Componenta\Auth\Session\Http\SessionCredentialPayload;
use Componenta\Auth\Session\RevocationReason;
use Componenta\Auth\Session\SessionCredential;
use Componenta\Identity\Uuid;
use DateTimeImmutable;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

final class AuthSessionGrantPublisherTest extends TestCase
{
    #[DataProvider('publicationStorages')]
    public function testLatestGrantFollowsPendingRestoreWithoutRevokingTheSession(bool $replacing): void
    {
        $restored = self::grant(1);
        $reauthenticated = self::grant(2);
        $sessions = $this->currentManager($reauthenticated);
        $sessions->expects(self::never())->method('revoke');
        $transport = new SessionCookieTransport();
        $state = new CredentialTransportState();
        $state->onDiscard(static function () use ($sessions, $restored): void {
            $sessions->revoke($restored->session->uuid, RevocationReason::SecurityEvent);
        });
        $state->queue($transport, new SessionCredentialPayload($restored->credential));
        $request = (new ServerRequest('POST', 'https://example.test/reauthenticate'))
            ->withAttribute(CredentialTransportState::class, $state);
        $response = new Response(204);
        $publisher = new AuthSessionGrantPublisher(
            $sessions,
            $replacing ? new ReplacingPayloadStorage($transport) : $transport,
        );

        $pending = $publisher->publish($request, $response, $reauthenticated);
        $published = $state->apply($request, $pending);

        self::assertStringStartsWith(
            '__Host-auth_session=' . $reauthenticated->credential->toString() . ';',
            $published->getHeaderLine('Set-Cookie'),
        );
        self::assertCount(1, $published->getHeader('Set-Cookie'));
        self::assertSame('no-store', $published->getHeaderLine('Cache-Control'));
        self::assertSame($response, $pending);
    }

    /** @return iterable<string, array{bool}> */
    public static function publicationStorages(): iterable
    {
        yield 'session cookie' => [false];
        yield 'replacing session cookie' => [true];
    }

    public function testGrantWithoutTransportStateIsPublishedImmediately(): void
    {
        $grant = self::grant(1);
        $sessions = $this->currentManager($grant);
        $sessions->expects(self::never())->method('revoke');

        $response = (new AuthSessionGrantPublisher($sessions, new SessionCookieTransport()))->publish(
            new ServerRequest('POST', 'https://example.test/login'),
            new Response(204),
            $grant,
        );

        self::assertStringStartsWith(
            '__Host-auth_session=' . $grant->credential->toString() . ';',
            $response->getHeaderLine('Set-Cookie'),
        );
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame('no-cache', $response->getHeaderLine('Pragma'));
    }

    #[DataProvider('publicationFailures')]
    public function testFailedPublicationRevokesTheUnpublishedGrant(bool $deferred, string $stage): void
    {
        $grant = self::grant(1);
        $sessions = $this->currentManager($grant);
        $sessions->expects(self::once())->method('revoke')
            ->with($grant->session->uuid, RevocationReason::SecurityEvent);
        $failure = new RuntimeException('Publication failed.');
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('remove');
        $response = new Response(204);

        if ($stage === 'store') {
            $storage->expects(self::once())->method('store')->willThrowException($failure);
        } else {
            $failingResponse = $this->createMock(ResponseInterface::class);
            $failingResponse->expects(self::once())->method('withHeader')->willThrowException($failure);
            $storage->expects(self::once())->method('store')->willReturn($failingResponse);
        }

        $request = new ServerRequest('POST', 'https://example.test/login');
        $publisher = new AuthSessionGrantPublisher($sessions, $storage);

        if ($deferred) {
            $state = new CredentialTransportState();
            $request = $request->withAttribute(CredentialTransportState::class, $state);
            $pending = $publisher->publish($request, $response, $grant);
            self::assertSame($response, $pending);

            $this->expectExceptionObject($failure);
            $state->apply($request, $pending);
        } else {
            $this->expectExceptionObject($failure);
            $publisher->publish($request, $response, $grant);
        }
    }

    /** @return iterable<string, array{bool, string}> */
    public static function publicationFailures(): iterable
    {
        yield 'immediate storage failure' => [false, 'store'];
        yield 'immediate response headers failure' => [false, 'headers'];
        yield 'deferred storage failure' => [true, 'store'];
        yield 'deferred response headers failure' => [true, 'headers'];
    }

    public function testTerminalClearRevokesAndRemovesTheUnpublishedGrant(): void
    {
        $grant = self::grant(1);
        $sessions = $this->currentManager($grant);
        $sessions->expects(self::once())->method('revoke')
            ->with($grant->session->uuid, RevocationReason::SecurityEvent);
        $transport = new SessionCookieTransport();
        $state = new CredentialTransportState();
        $state->clear($transport);
        $request = (new ServerRequest('POST', 'https://example.test/login'))
            ->withAttribute(CredentialTransportState::class, $state);
        $response = new Response(204);

        $pending = (new AuthSessionGrantPublisher($sessions, $transport))->publish($request, $response, $grant);
        $published = $state->apply($request, $pending);

        self::assertSame($response, $pending);
        self::assertStringStartsWith('__Host-auth_session=;', $published->getHeaderLine('Set-Cookie'));
        self::assertStringContainsString('Max-Age=0', $published->getHeaderLine('Set-Cookie'));
        self::assertSame('no-store', $published->getHeaderLine('Cache-Control'));
    }

    public function testSynchronousDiscardFailureIsNotCompensatedAgain(): void
    {
        $grant = self::grant(1);
        $sessions = $this->currentManager($grant);
        $failure = new RuntimeException('Compensation failed.');
        $sessions->expects(self::once())->method('revoke')
            ->with($grant->session->uuid, RevocationReason::SecurityEvent)
            ->willThrowException($failure);
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('store');
        $state = new CredentialTransportState();
        $state->clear($storage);
        $request = (new ServerRequest('POST', 'https://example.test/login'))
            ->withAttribute(CredentialTransportState::class, $state);

        $this->expectExceptionObject($failure);

        (new AuthSessionGrantPublisher($sessions, $storage))->publish($request, new Response(204), $grant);
    }

    public function testFailedTransportStateLookupRevokesTheUnpublishedGrant(): void
    {
        $grant = self::grant(1);
        $sessions = $this->currentManager($grant);
        $sessions->expects(self::once())->method('revoke')
            ->with($grant->session->uuid, RevocationReason::SecurityEvent);
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('store');
        $failure = new RuntimeException('Request attribute lookup failed.');
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(self::once())->method('getAttribute')
            ->with(CredentialTransportState::class)->willThrowException($failure);

        $this->expectExceptionObject($failure);

        (new AuthSessionGrantPublisher($sessions, $storage))->publish($request, new Response(204), $grant);
    }

    #[DataProvider('transportStates')]
    public function testOutdatedGrantIsRejectedWithoutRevokingTheCurrentSession(bool $deferred): void
    {
        $grant = self::grant(1);
        $sessions = $this->createMock(AuthSessionManagerInterface::class);
        $sessions->expects(self::once())->method('isGrantCurrent')->with($grant)->willReturn(false);
        $sessions->expects(self::never())->method('revoke');
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('store');
        $request = new ServerRequest('POST', 'https://example.test/login');

        if ($deferred) {
            $request = $request->withAttribute(CredentialTransportState::class, new CredentialTransportState());
        }

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Authentication-session grant is no longer current.');

        (new AuthSessionGrantPublisher($sessions, $storage))->publish($request, new Response(204), $grant);
    }

    /** @return iterable<string, array{bool}> */
    public static function transportStates(): iterable
    {
        yield 'without transport owner' => [false];
        yield 'with transport owner' => [true];
    }

    private function currentManager(AuthSessionGrant $grant): AuthSessionManagerInterface&MockObject
    {
        $sessions = $this->createMock(AuthSessionManagerInterface::class);
        $sessions->expects(self::once())->method('isGrantCurrent')->with($grant)->willReturn(true);

        return $sessions;
    }

    private static function grant(int $generation): AuthSessionGrant
    {
        $now = new DateTimeImmutable('2030-01-01T00:00:00+00:00');

        return new AuthSessionGrant(
            new AuthSession(
                uuid: Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
                subjectId: Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abd'),
                evidence: new AuthenticationEvidence(['password']),
                credentialGeneration: $generation,
                authenticatedAt: $now,
                reauthenticatedAt: null,
                lastActiveAt: $now,
                idleExpiresAt: $now->modify('+30 minutes'),
                absoluteExpiresAt: $now->modify('+8 hours'),
            ),
            SessionCredential::fromString(str_repeat((string) $generation, 43)),
        );
    }
}
