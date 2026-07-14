<?php

declare(strict_types=1);

namespace SlimJwtAuth;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use InvalidArgumentException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use SlimJwtAuth\Rules\RequestMethodRule;
use SlimJwtAuth\Rules\RequestPathRule;
use SlimJwtAuth\Support\ResolvesResponseFactory;
use Throwable;

/**
 * PSR-15 JWT authentication middleware for Slim 4.
 *
 * API is intentionally close to tuupola/slim-jwt-auth so migrating is mostly
 * a namespace swap:
 *
 *   $app->add(new JwtAuthMiddleware([
 *       'secret'  => 'supersecretkeyyoushouldnotcommittogithub',
 *       'path'    => ['/api'],
 *       'ignore'  => ['/api/login'],
 *       'error'   => function (ResponseInterface $response, array $arguments) {
 *           $response->getBody()->write(json_encode(['error' => $arguments['message']]));
 *           return $response;
 *       },
 *   ]));
 *
 * Decoded claims are attached to the request as an attribute (default name
 * "token") and can be read in your route handlers via
 * $request->getAttribute('token').
 */
final class JwtAuthMiddleware implements MiddlewareInterface
{
    use ResolvesResponseFactory;

    private const array DEFAULTS = [
        'secret' => null,
        'algorithm' => 'HS256',
        'header' => 'Authorization',
        'regexp' => '/Bearer\s+(.*)$/i',
        'cookie' => 'token',
        'attribute' => 'token',
        'path' => ['/'],
        'ignore' => [],
        'before' => null,
        'after' => null,
        'error' => null,
        'secure' => true,
        'relaxed' => ['localhost', '127.0.0.1'],
        'leeway' => 0,
        'response_factory' => null,
    ];

    private readonly array $options;

    /** @var RuleInterface[] */
    private readonly array $rules;

    private readonly ResponseFactoryInterface $responseFactory;

    public function __construct(array $options = [])
    {
        if (empty($options['secret'])) {
            throw new InvalidArgumentException('JWT "secret" option is required.');
        }

        $this->options = array_replace(self::DEFAULTS, $options);

        JWT::$leeway = (int) $this->options['leeway'];

        $this->rules = $options['rules'] ?? [
            new RequestMethodRule(['OPTIONS']),
            new RequestPathRule(
                path: (array) $this->options['path'],
                ignore: (array) $this->options['ignore'],
            ),
        ];

        $this->responseFactory = $this->resolveResponseFactory($this->options['response_factory']);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!$this->shouldAuthenticate($request)) {
            return $handler->handle($request);
        }

        if (!$this->isSecure($request)) {
            return $this->respondWithError($request, 'Insecure use of middleware over HTTP denied by configuration.', 400);
        }

        $token = $this->fetchToken($request);

        if ($token === null) {
            return $this->respondWithError($request, 'Token not found.', 401);
        }

        try {
            $decoded = JWT::decode($token, $this->buildKeys());
        } catch (Throwable $exception) {
            return $this->respondWithError($request, $exception->getMessage(), 401);
        }

        $claims = (array) $decoded;

        if ($this->options['attribute'] !== false) {
            $request = $request->withAttribute((string) $this->options['attribute'], $decoded);
        }

        if (is_callable($this->options['before'])) {
            $result = ($this->options['before'])($request, $claims);
            if ($result instanceof ServerRequestInterface) {
                $request = $result;
            }
        }

        $response = $handler->handle($request);

        if (is_callable($this->options['after'])) {
            $result = ($this->options['after'])($response, $claims);
            if ($result instanceof ResponseInterface) {
                $response = $result;
            }
        }

        return $response;
    }

    private function shouldAuthenticate(ServerRequestInterface $request): bool
    {
        foreach ($this->rules as $rule) {
            if (!$rule->shouldAuthenticate($request)) {
                return false;
            }
        }

        return true;
    }

    private function isSecure(ServerRequestInterface $request): bool
    {
        if ($this->options['secure'] === false) {
            return true;
        }

        $uri = $request->getUri();

        return $uri->getScheme() === 'https'
            || in_array($uri->getHost(), (array) $this->options['relaxed'], true);
    }

    private function fetchToken(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine($this->options['header']);

        if ($header !== '' && preg_match($this->options['regexp'], $header, $matches) === 1) {
            return $matches[1];
        }

        $cookies = $request->getCookieParams();
        $cookieName = $this->options['cookie'];

        if ($cookieName !== false && isset($cookies[$cookieName]) && is_string($cookies[$cookieName])) {
            return $cookies[$cookieName];
        }

        return null;
    }

    /**
     * Builds what firebase/php-jwt 6.x expects: a single Key, or a
     * [kid => Key] map when multiple keys are configured (key rotation /
     * JWKS-style setups).
     *
     * secret can be:
     *   - a plain string                      -> single Key, $options['algorithm']
     *   - ['kid1' => 'secret1', 'kid2' => ...] -> map keyed by kid, same algorithm
     *   - ['kid1' => ['secret1', 'RS256'], ...]-> map keyed by kid, per-key algorithm
     */
    private function buildKeys(): Key|array
    {
        $secret = $this->options['secret'];
        $defaultAlgorithm = $this->options['algorithm'];

        if (!is_array($secret)) {
            return new Key($secret, $defaultAlgorithm);
        }

        $keys = [];
        foreach ($secret as $kid => $value) {
            [$keyMaterial, $algorithm] = is_array($value)
                ? [$value[0], $value[1] ?? $defaultAlgorithm]
                : [$value, $defaultAlgorithm];

            $keys[$kid] = new Key($keyMaterial, $algorithm);
        }

        return $keys;
    }

    private function respondWithError(ServerRequestInterface $request, string $message, int $status): ResponseInterface
    {
        $response = $this->responseFactory->createResponse($status);

        if (is_callable($this->options['error'])) {
            $result = ($this->options['error'])($response, ['message' => $message, 'request' => $request]);
            if ($result instanceof ResponseInterface) {
                return $result;
            }
        }

        $response->getBody()->write(json_encode(['error' => $message], JSON_THROW_ON_ERROR));

        return $response->withHeader('Content-Type', 'application/json');
    }

}
