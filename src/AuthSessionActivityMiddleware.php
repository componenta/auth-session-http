<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http;

use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class AuthSessionActivityMiddleware implements MiddlewareInterface
{
    public function __construct(private AuthSessionManagerInterface $sessions) {}

    #[\Override]
    public function process(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
        #[\SensitiveParameter]
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $response = $handler->handle($request);
        $session = $request->getAttribute(AuthSession::class);

        if ($session instanceof AuthSession) {
            $this->sessions->touch($session);
        }

        return $response;
    }
}
