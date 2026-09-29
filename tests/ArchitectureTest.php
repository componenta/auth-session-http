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
        $interfaces = class_implements(AuthSession::class);

        self::assertIsArray($interfaces);
        self::assertArrayHasKey(AuthenticationStateInterface::class, $interfaces);
    }

    public function testPackageDoesNotDependOnLegacySessionComponent(): void
    {
        $path = dirname(__DIR__) . '/composer.json';
        $json = file_get_contents($path);

        self::assertIsString($json);

        $composer = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($composer);

        $requires = $composer['require'] ?? null;
        self::assertIsArray($requires);

        self::assertArrayNotHasKey('componenta/session', $requires);
        self::assertArrayNotHasKey('componenta/auth-session-csrf', $requires);
        self::assertArrayHasKey('componenta/http-csrf-middleware', $requires);
    }
}
