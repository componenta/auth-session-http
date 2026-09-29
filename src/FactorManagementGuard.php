<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http;

use Componenta\Auth\AuthenticationAdmission;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Session\AssuranceRequirement;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionRegistryInterface;
use Componenta\Auth\Session\Http\Csrf\AuthSessionCsrfMiddleware;
use Componenta\Identity\IdentityInterface;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Mandatory browser gate for enrollment, factor replacement and recovery-code
 * regeneration. The application selects the permitted existing-factor evidence;
 * bootstrap and replacement policies must not be conflated.
 */
final readonly class FactorManagementGuard
{
    /** @param list<string> $trustedOrigins */
    public function __construct(
        private AuthSessionRegistryInterface $sessions,
        private AuthenticationAdmission $admission,
        private AssuranceRequirement $requirement,
        private ClockInterface $clock,
        private ResponseFactoryInterface $responses,
        #[\SensitiveParameter]
        private string $csrfKey,
        private array $trustedOrigins = [],
    ) {
        if (
            $requirement->maxAge === null
            || $requirement->maxAge < 1
            || $requirement->maxAge > 600
            || ($requirement->requiredMethods === [] && $requirement->requiredCapabilities === [])
        ) {
            throw new \InvalidArgumentException('Factor management requires explicit assurance no older than 600 seconds.');
        }
        if (strlen($csrfKey) < 32 || strlen($csrfKey) > 4096) {
            throw new \InvalidArgumentException('CSRF key must contain between 32 and 4096 bytes.');
        }
    }

    /** Returns a terminal refusal, or null only when every check succeeds. */
    public function check(#[\SensitiveParameter] ServerRequestInterface $request): ?ResponseInterface
    {
        if ($request->getMethod() !== 'POST') {
            return $this->refuse(405)->withHeader('Allow', 'POST');
        }
        $observed = $request->getAttribute(AuthSession::class);
        $identity = $request->getAttribute(IdentityInterface::class);
        if (!$observed instanceof AuthSession || !$identity instanceof IdentityInterface) {
            return $this->refuse(401);
        }
        $current = $this->sessions->find($observed->uuid);
        $now = $this->clock->now();
        if (
            $current === null
            || !$current->uuid->equals($observed->uuid)
            || !$current->subjectId->equals($identity->uuid)
            || !$current->subjectId->equals($observed->subjectId)
            || $current->credentialGeneration !== $observed->credentialGeneration
            || $current->idleExpiresAt <= $now
            || $current->absoluteExpiresAt <= $now
        ) {
            return $this->refuse(401);
        }
        if (
            !$this->requirement->isSatisfiedBy($current, $now)
            || $this->admission->check($current->subjectId, $current->evidence) instanceof DeniedReasonInterface
        ) {
            return $this->refuse(403);
        }

        // Deliberately no path exemptions or origin-check bypass. The token is
        // validated against authoritative session generation, not request data.
        $accepted = new class($this->responses->createResponse(204)) implements RequestHandlerInterface {
            public bool $called = false;

            public function __construct(private readonly ResponseInterface $response) {}

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->called = true;

                return $this->response;
            }
        };

        (new AuthSessionCsrfMiddleware(
            responses: $this->responses,
            key: $this->csrfKey,
            trustedOrigins: $this->trustedOrigins,
        ))->process(
            $request->withAttribute(AuthSession::class, $current),
            $accepted,
        );

        return $accepted->called ? null : $this->refuse(403);
    }

    /** @return array{csrfKey: string} */
    public function __debugInfo(): array
    {
        return ['csrfKey' => '[REDACTED]'];
    }

    private function refuse(int $status): ResponseInterface
    {
        return $this->responses->createResponse($status)
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }
}
