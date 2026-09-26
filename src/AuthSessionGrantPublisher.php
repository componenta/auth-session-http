<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http;

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
            return $this->storage->store(
                $request,
                $response,
                new SessionCredentialPayload($grant->credential),
            );
        } catch (\Throwable $exception) {
            $this->sessions->revoke(
                $grant->session->uuid,
                RevocationReason::SecurityEvent,
            );

            throw $exception;
        }
    }
}
