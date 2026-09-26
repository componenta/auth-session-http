<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http;

use Componenta\Auth\Session\PreAuthenticationManagerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Starts a browser-bound pre-authentication transaction.
 *
 * Useful for login methods that do not otherwise have a request/challenge
 * endpoint, such as password login.
 */
final readonly class PreAuthenticationStartHandler implements
    RequestHandlerInterface
{
    public function __construct(
        private PreAuthenticationManagerInterface $transactions,
        private PreAuthenticationGrantPublisher $publisher,
        private ResponseFactoryInterface $responses,
        private int $ttlSeconds = 300,
    ) {
        if ($this->ttlSeconds < 30 || $this->ttlSeconds > 1800) {
            throw new \InvalidArgumentException(
                'Pre-authentication TTL must be between 30 and 1800 seconds.',
            );
        }
    }

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $grant = $this->transactions->create($this->ttlSeconds);

        return $this->publisher->publish(
            $this->responses->createResponse(204),
            $grant,
        );
    }
}
