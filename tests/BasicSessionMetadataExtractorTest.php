<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http\Tests;

use Componenta\Auth\Session\Http\BasicSessionMetadataExtractor;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class BasicSessionMetadataExtractorTest extends TestCase
{
    public function testExtractsOnlyDirectBoundedMetadata(): void
    {
        $request = (new ServerRequest(
            'GET',
            '/',
            ['User-Agent' => 'ExampleBrowser/1.0'],
            null,
            '1.1',
            ['REMOTE_ADDR' => '203.0.113.10'],
        ))->withHeader('X-Forwarded-For', '198.51.100.99');

        self::assertSame(
            [
                'userAgent' => 'ExampleBrowser/1.0',
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
}
