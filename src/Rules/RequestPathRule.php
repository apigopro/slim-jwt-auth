<?php

declare(strict_types=1);

namespace SlimJwtAuth\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SlimJwtAuth\RuleInterface;

/**
 * Authenticates requests whose path matches one of the `path` patterns,
 * unless it also matches one of the `ignore` patterns. Patterns support a
 * trailing "*" wildcard, e.g. "/api/*" or "/api/login".
 */
final class RequestPathRule implements RuleInterface
{
    /** @var string[] */
    private readonly array $path;

    /** @var string[] */
    private readonly array $ignore;

    /**
     * @param string[] $path
     * @param string[] $ignore
     */
    public function __construct(array $path = ['/'], array $ignore = [])
    {
        $this->path = $path;
        $this->ignore = $ignore;
    }

    public function shouldAuthenticate(ServerRequestInterface $request): bool
    {
        $uri = '/' . ltrim($request->getUri()->getPath(), '/');

        foreach ($this->ignore as $pattern) {
            if ($this->matches($pattern, $uri)) {
                return false;
            }
        }

        foreach ($this->path as $pattern) {
            if ($this->matches($pattern, $uri)) {
                return true;
            }
        }

        return false;
    }

    /**
     * A pattern containing "*" is matched as an explicit wildcard regexp.
     * A plain pattern (no wildcard) is matched as a path *prefix*, so
     * "/api" matches "/api", "/api/orders", "/api/orders/42", etc. — this
     * mirrors tuupola/slim-jwt-auth's original behaviour, where "path" is a
     * mount point rather than a single exact route.
     */
    private function matches(string $pattern, string $uri): bool
    {
        $pattern = '/' . ltrim($pattern, '/');

        if (str_contains($pattern, '*')) {
            $regexp = '#^' . str_replace('\*', '.*', preg_quote($pattern, '#')) . '$#';
            return (bool) preg_match($regexp, $uri);
        }

        $pattern = rtrim($pattern, '/');

        return $uri === $pattern || str_starts_with($uri, $pattern . '/');
    }
}
