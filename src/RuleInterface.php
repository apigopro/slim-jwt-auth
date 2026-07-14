<?php

declare(strict_types=1);

namespace SlimJwtAuth;

use Psr\Http\Message\ServerRequestInterface;

/**
 * A rule decides whether the incoming request should be authenticated.
 * The middleware authenticates only if EVERY registered rule returns true,
 * exactly like tuupola/slim-jwt-auth did.
 */
interface RuleInterface
{
    public function shouldAuthenticate(ServerRequestInterface $request): bool;
}
