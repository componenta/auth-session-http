<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http;

use Componenta\Auth\Http\CredentialResponseHeaders;
use Componenta\Auth\Session\PreAuthenticationGrant;
use Psr\Http\Message\ResponseInterface;

final readonly class PreAuthenticationGrantPublisher
{
    public function __construct(
        private PreAuthenticationCookieTransport $cookies,
        private string $requestTokenHeader = 'X-Pre-Auth-Token',
    ) {
        if (
            preg_match(
                '/\A[!#$%&\'*+.^_\x60|~0-9A-Za-z-]+\z/D',
                $this->requestTokenHeader,
            ) !== 1
        ) {
            throw new \InvalidArgumentException(
                'Pre-authentication request-token header name is invalid.',
            );
        }
    }

    public function publish(
        #[\SensitiveParameter]
        ResponseInterface $response,
        #[\SensitiveParameter]
        PreAuthenticationGrant $grant,
    ): ResponseInterface {
        return CredentialResponseHeaders::apply(
            $this->cookies
                ->store($response, $grant->credential)
                ->withHeader(
                    $this->requestTokenHeader,
                    $grant->requestToken->toString(),
                ),
        );
    }

    public function clear(ResponseInterface $response): ResponseInterface
    {
        return CredentialResponseHeaders::apply(
            $this->cookies->remove($response)
                ->withoutHeader($this->requestTokenHeader),
        );
    }
}
