<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http;

use Psr\Http\Message\ServerRequestInterface;

interface SessionMetadataExtractorInterface
{
    /** @return array<string, scalar|null> */
    public function extract(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): array;
}
