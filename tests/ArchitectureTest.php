<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Tests;

use Componenta\Auth\AuthenticationStateInterface;
use Componenta\Auth\Session\AuthSession;
use PHPUnit\Framework\TestCase;

final class ArchitectureTest extends TestCase
{
    public function testAuthSessionIsTheTypedAuthenticationState(): void
    {
        self::assertTrue(
            is_a(
                AuthSession::class,
                AuthenticationStateInterface::class,
                true,
            ),
        );
    }

    public function testPackageDoesNotDependOnLegacySessionComponent(): void
    {
        $composer = json_decode(
            file_get_contents(dirname(__DIR__) . '/composer.json'),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        self::assertIsArray($composer);
        $requires = $composer['require'] ?? [];

        self::assertArrayNotHasKey('componenta/session', $requires);
        self::assertArrayNotHasKey(
            'componenta/auth-session-csrf',
            $requires,
        );
        self::assertArrayHasKey(
            'componenta/http-csrf-middleware',
            $requires,
        );
    }
}
