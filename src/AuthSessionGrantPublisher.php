<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http;

use Componenta\Auth\Http\CredentialResponseHeaders;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Session\AuthSessionGrant;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\RevocationReason;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class AuthSessionGrantPublisher
{
    public function __construct(
        private AuthSessionManagerInterface $sessions,
        private PayloadStorageInterface $storage,
    ) {}

    /** An existing transport state owns deferred publication and compensation. */
    public function publish(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
        #[\SensitiveParameter]
        ResponseInterface $response,
        #[\SensitiveParameter]
        AuthSessionGrant $grant,
    ): ResponseInterface {
        if (!$this->sessions->isGrantCurrent($grant)) {
            throw new \RuntimeException(
                'Authentication-session grant is no longer current.',
            );
        }

        try {
            $state = $request->getAttribute(CredentialTransportState::class);

            if (!$state instanceof CredentialTransportState) {
                return CredentialResponseHeaders::apply(
                    $this->storage->store(
                        $request,
                        $response,
                        new SessionCredentialPayload($grant->credential),
                    ),
                );
            }
        } catch (\Throwable $exception) {
            $this->sessions->revoke(
                $grant->session->uuid,
                RevocationReason::SecurityEvent,
            );

            throw $exception;
        }

        // Registration transfers ownership, including synchronous discard when
        // the state is already cleared. Do not compensate a failing callback twice.
        $state->onDiscard(function () use ($grant): void {
            $this->sessions->revoke(
                $grant->session->uuid,
                RevocationReason::SecurityEvent,
            );
        });
        $state->queue($this->storage, new SessionCredentialPayload($grant->credential));

        return $response;
    }
}
