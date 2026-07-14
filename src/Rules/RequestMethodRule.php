<?php

declare(strict_types=1);

namespace SlimJwtAuth\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SlimJwtAuth\RuleInterface;

/**
 * Skips authentication for the given HTTP methods. Defaults to OPTIONS so
 * CORS preflight requests are never blocked.
 */
final class RequestMethodRule implements RuleInterface
{
    /** @var string[] */
    private readonly array $ignore;

    /** @param string[] $ignore */
    public function __construct(array $ignore = ['OPTIONS'])
    {
        $this->ignore = array_map(strtoupper(...), $ignore);
    }

    public function shouldAuthenticate(ServerRequestInterface $request): bool
    {
        return !in_array(strtoupper($request->getMethod()), $this->ignore, true);
    }
}
