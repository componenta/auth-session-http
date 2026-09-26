<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http;

use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Extends idle lifetime only for explicitly classified interactive requests.
 *
 * Put SessionActivity::Interactive into the PSR-7 request attribute keyed by
 * SessionActivity::class. Unclassified/background requests fail safe and do
 * not extend the session. Authentication/authorization denials (401/403) also
 * never extend activity.
 */
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
        $activity = $request->getAttribute(SessionActivity::class);
        $status = $response->getStatusCode();

        if (
            $session instanceof AuthSession
            && $activity === SessionActivity::Interactive
            && $status !== 401
            && $status !== 403
        ) {
            $this->sessions->touch($session);
        }

        return $response;
    }
}
