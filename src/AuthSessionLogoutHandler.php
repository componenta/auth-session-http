<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http;

use Componenta\Auth\Http\CredentialResponseHeaders;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\RevocationReason;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class AuthSessionLogoutHandler implements RequestHandlerInterface
{
    public function __construct(
        private SessionCookieTransport $transport,
        private AuthSessionManagerInterface $sessions,
        private ResponseFactoryInterface $responses,
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $payload = $this->transport->extract($request);

        if ($payload instanceof SessionCredentialPayload) {
            $this->sessions->revokePresentedCredential(
                $payload->credential,
                RevocationReason::Logout,
            );
        }

        return CredentialResponseHeaders::apply(
            $this->transport->remove(
                $request,
                $this->responses->createResponse(204),
            ),
        );
    }
}
