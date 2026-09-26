<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http;

use Componenta\Auth\Http\Exception\InvalidPayloadException;
use Componenta\Auth\Session\PreAuthenticationManagerInterface;
use Componenta\Auth\Session\PreAuthenticationRequestToken;
use Componenta\Auth\Session\PreAuthenticationTransaction;
use Psr\Http\Message\ServerRequestInterface;

final readonly class PreAuthenticationConsumer
{
    public function __construct(
        private PreAuthenticationManagerInterface $transactions,
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

    public function consume(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ?PreAuthenticationTransaction {
        $credential = $this->cookies->extract($request);

        if ($credential === null) {
            return null;
        }

        $value = $request->getHeaderLine($this->requestTokenHeader);

        if ($value === '') {
            throw InvalidPayloadException::missingField(
                $this->requestTokenHeader,
            );
        }

        try {
            $requestToken = PreAuthenticationRequestToken::fromString($value);
        } catch (\InvalidArgumentException) {
            throw InvalidPayloadException::invalidField(
                $this->requestTokenHeader,
            );
        }

        return $this->transactions->consume($credential, $requestToken);
    }
}
