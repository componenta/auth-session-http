<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Tests;

use Componenta\Auth\Session\Http\BasicSessionMetadataExtractor;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class BasicSessionMetadataExtractorTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function validUserAgents(): iterable
    {
        yield 'ASCII' => ['ExampleBrowser/1.0'];
        yield 'UTF-8' => ['ExampleBrowser/1.0 (é; 日本語)'];
    }

    #[DataProvider('validUserAgents')]
    public function testExtractsOnlyDirectBoundedMetadata(string $userAgent): void
    {
        $request = (new ServerRequest(
            'GET',
            '/',
            ['User-Agent' => $userAgent],
            null,
            '1.1',
            ['REMOTE_ADDR' => '203.0.113.10'],
        ))->withHeader('X-Forwarded-For', '198.51.100.99');

        self::assertSame(
            [
                'userAgent' => $userAgent,
                'ip' => '203.0.113.10',
            ],
            (new BasicSessionMetadataExtractor())->extract($request),
        );
    }

    public function testIgnoresMalformedMetadata(): void
    {
        $request = new ServerRequest(
            'GET',
            '/',
            ['User-Agent' => str_repeat('x', 1025)],
            null,
            '1.1',
            ['REMOTE_ADDR' => 'not-an-ip'],
        );

        self::assertSame(
            [],
            (new BasicSessionMetadataExtractor())->extract($request),
        );
    }

    public function testInvalidUtf8UserAgentDoesNotPreventRecordingValidMetadata(): void
    {
        $request = new ServerRequest(
            'POST',
            '/login',
            ['User-Agent' => "ExampleBrowser/1.0 (\xE9)"],
            null,
            '1.1',
            ['REMOTE_ADDR' => '203.0.113.10'],
        );

        self::assertSame(
            ['ip' => '203.0.113.10'],
            (new BasicSessionMetadataExtractor())->extract($request),
        );
    }
}
