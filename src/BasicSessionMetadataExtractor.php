<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Conservative metadata extractor.
 *
 * It deliberately does not inspect X-Forwarded-For or similar proxy headers.
 * Applications with a trusted-proxy policy can provide their own extractor.
 */
final readonly class BasicSessionMetadataExtractor implements
    SessionMetadataExtractorInterface
{
    #[\Override]
    public function extract(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): array {
        $metadata = [];
        $userAgent = $request->getHeaderLine('User-Agent');

        if (
            $userAgent !== ''
            && strlen($userAgent) <= 1024
            && preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $userAgent) !== 1
        ) {
            $metadata['userAgent'] = $userAgent;
        }

        $remoteAddress = $request->getServerParams()['REMOTE_ADDR'] ?? null;

        if (
            is_string($remoteAddress)
            && filter_var($remoteAddress, FILTER_VALIDATE_IP) !== false
        ) {
            $metadata['ip'] = $remoteAddress;
        }

        return $metadata;
    }
}
