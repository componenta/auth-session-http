<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Session\AuthSessionManagerInterface;

final readonly class SessionAuthenticationStrategy implements AuthenticationStrategyInterface
{
    public function __construct(
        private AuthSessionManagerInterface $sessions,
        private IdentityProviderInterface $identities,
    ) {}

    #[\Override]
    public function supports(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): bool {
        return $payload instanceof SessionCredentialPayload;
    }

    #[\Override]
    public function attempt(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): AuthenticationResult {
        if (!$payload instanceof SessionCredentialPayload) {
            return $this->denied();
        }

        $session = $this->sessions->resume($payload->credential);

        if ($session === null) {
            return $this->denied();
        }

        $identity = $this->identities->findByUuid($session->subjectId);

        if (
            $identity === null
            || !$identity->uuid->equals($session->subjectId)
        ) {
            return $this->denied();
        }

        return new AuthenticationResult(
            subject: $identity,
            state: $session,
            evidence: $session->evidence,
        );
    }

    private function denied(): AuthenticationResult
    {
        return new AuthenticationResult(
            new InvalidCredentials(),
            continueOnFailure: true,
        );
    }
}
