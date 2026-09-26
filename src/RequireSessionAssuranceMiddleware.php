<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http;

use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Session\AssuranceRequirement;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\Denied\InsufficientAssurance;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class RequireSessionAssuranceMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AssuranceRequirement $requirement,
        private ClockInterface $clock,
        private DeniedResponseFactoryInterface $deniedResponses,
    ) {}

    #[\Override]
    public function process(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
        #[\SensitiveParameter]
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $session = $request->getAttribute(AuthSession::class);

        if (
            $session instanceof AuthSession
            && $this->requirement->isSatisfiedBy($session, $this->clock->now())
        ) {
            return $handler->handle($request);
        }

        return $this->deniedResponses->create(new InsufficientAssurance());
    }
}
