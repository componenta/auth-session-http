<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Csrf;

use Componenta\Auth\Session\AuthSession;
use Componenta\Http\Middleware\Csrf\CsrfMiddleware;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class AuthSessionCsrfMiddleware implements MiddlewareInterface
{
    /**
     * @param list<string> $trustedOrigins
     * @param list<string> $excludedPaths
     */
    public function __construct(
        private ResponseFactoryInterface $responses,
        #[\SensitiveParameter]
        private string $key,
        private string $headerName = 'X-CSRF-Token',
        private string $fieldName = '_csrf_token',
        private bool $checkOrigin = true,
        private array $trustedOrigins = [],
        private array $excludedPaths = [],
        private bool $checkFetchMetadata = true,
        private bool $allowMissingOrigin = false,
        private bool $debugFailureHeader = false,
    ) {}

    #[\Override]
    public function process(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
        #[\SensitiveParameter]
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $session = $request->getAttribute(AuthSession::class);

        if (!$session instanceof AuthSession) {
            return $this->responses->createResponse(403)
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache');
        }

        return (new CsrfMiddleware(
            tokenManager: new AuthSessionCsrfTokenManager($session, $this->key),
            responseFactory: $this->responses,
            headerName: $this->headerName,
            fieldName: $this->fieldName,
            checkOrigin: $this->checkOrigin,
            trustedOrigins: $this->trustedOrigins,
            excludedPaths: $this->excludedPaths,
            checkFetchMetadata: $this->checkFetchMetadata,
            allowMissingOrigin: $this->allowMissingOrigin,
            debugFailureHeader: $this->debugFailureHeader,
        ))->process($request, $handler);
    }
}
