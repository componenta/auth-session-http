<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http;

use Componenta\Auth\Http\Exception\InvalidPayloadException;
use Componenta\Auth\Session\PreAuthenticationCredential;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class PreAuthenticationCookieTransport
{
    public string $sameSite;

    public function __construct(
        public string $name = '__Host-auth_pre',
        string $sameSite = 'Lax',
    ) {
        if (
            !str_starts_with($this->name, '__Host-')
            || preg_match('/\A[!#$%&\'*+.^_\x60|~0-9A-Za-z-]+\z/D', $this->name) !== 1
        ) {
            throw new \InvalidArgumentException(
                'Pre-authentication cookie must use a valid __Host- name.',
            );
        }

        $this->sameSite = match (strtolower($sameSite)) {
            'lax' => 'Lax',
            'strict' => 'Strict',
            'none' => 'None',
            default => throw new \InvalidArgumentException(
                'SameSite must be Lax, Strict or None.',
            ),
        };
    }

    public function extract(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ?PreAuthenticationCredential {
        $cookies = $request->getCookieParams();

        if (!array_key_exists($this->name, $cookies)) {
            return null;
        }

        $value = $cookies[$this->name];

        if (!is_string($value) || $value === '') {
            throw InvalidPayloadException::invalidField($this->name);
        }

        try {
            return PreAuthenticationCredential::fromString($value);
        } catch (\InvalidArgumentException) {
            throw InvalidPayloadException::invalidField($this->name);
        }
    }

    public function store(
        ResponseInterface $response,
        #[\SensitiveParameter]
        PreAuthenticationCredential $credential,
    ): ResponseInterface {
        return $this->replaceCookie(
            $response,
            $this->cookie($credential->toString()),
        );
    }

    public function remove(ResponseInterface $response): ResponseInterface
    {
        return $this->replaceCookie(
            $response,
            $this->cookie('', 'Thu, 01 Jan 1970 00:00:00 GMT', 0),
        );
    }

    private function cookie(
        #[\SensitiveParameter]
        string $value,
        ?string $expires = null,
        ?int $maxAge = null,
    ): string {
        $parts = [
            sprintf('%s=%s', $this->name, rawurlencode($value)),
            'Path=/',
            sprintf('SameSite=%s', $this->sameSite),
            'Secure',
            'HttpOnly',
        ];

        if ($expires !== null) {
            $parts[] = 'Expires=' . $expires;
        }

        if ($maxAge !== null) {
            $parts[] = 'Max-Age=' . $maxAge;
        }

        return implode('; ', $parts);
    }

    private function replaceCookie(
        ResponseInterface $response,
        #[\SensitiveParameter]
        string $cookie,
    ): ResponseInterface {
        $existing = array_filter(
            $response->getHeader('Set-Cookie'),
            fn(string $header): bool => !str_starts_with(
                $header,
                $this->name . '=',
            ),
        );
        $response = $response->withoutHeader('Set-Cookie');

        foreach ($existing as $header) {
            $response = $response->withAddedHeader('Set-Cookie', $header);
        }

        return $response->withAddedHeader('Set-Cookie', $cookie);
    }
}
