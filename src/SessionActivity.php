<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Http;

enum SessionActivity
{
    case Interactive;
    case Background;
}
