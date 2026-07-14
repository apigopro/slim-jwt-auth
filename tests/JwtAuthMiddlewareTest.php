<?php

declare(strict_types=1);

namespace SlimJwtAuth\Tests;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use SlimJwtAuth\JwtAuthMiddleware;

final class JwtAuthMiddlewareTest extends TestCase
{
    private const SECRET = 'super-secret-test-key-thats-long-enough';

    private function handler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $response = (new ResponseFactory())->createResponse(200);
                $token = $request->getAttribute('token');
                $response->getBody()->write($token !== null ? 'ok:' . $token->sub : 'ok');
                return $response;
            }
        };
    }

    private function token(array $claims = [], string $secret = self::SECRET, string $alg = 'HS256'): string
    {
        return JWT::encode(array_merge(['sub' => 'user-1', 'exp' => time() + 3600], $claims), $secret, $alg);
    }

    public function testValidTokenPassesThrough(): void
    {
        $middleware = new JwtAuthMiddleware(['secret' => self::SECRET, 'path' => ['/api']]);

        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api/orders')
            ->withHeader('Authorization', 'Bearer ' . $this->token());

        $response = $middleware->process($request, $this->handler());

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('ok:user-1', (string) $response->getBody());
    }

    public function testMissingTokenIsRejected(): void
    {
        $middleware = new JwtAuthMiddleware(['secret' => self::SECRET, 'path' => ['/api']]);
        $request = (new ServerRequestFactory())->createServerRequest('GET', 'https://example.com/api/orders');

        $response = $middleware->process($request, $this->handler());

        $this->assertSame(401, $response->getStatusCode());
    }

    public function testExpiredTokenIsRejected(): void
    {
        $middleware = new JwtAuthMiddleware(['secret' => self::SECRET, 'path' => ['/api']]);
        $expired = $this->token(['exp' => time() - 100]);

        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api/orders')
            ->withHeader('Authorization', 'Bearer ' . $expired);

        $response = $middleware->process($request, $this->handler());

        $this->assertSame(401, $response->getStatusCode());
    }

    public function testIgnoredPathSkipsAuthentication(): void
    {
        $middleware = new JwtAuthMiddleware([
            'secret' => self::SECRET,
            'path' => ['/api'],
            'ignore' => ['/api/login'],
        ]);

        $request = (new ServerRequestFactory())->createServerRequest('POST', 'https://example.com/api/login');
        $response = $middleware->process($request, $this->handler());

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testKidBasedKeyRotation(): void
    {
        $middleware = new JwtAuthMiddleware([
            'secret' => [
                'key-a' => 'secret-for-key-a-that-is-definitely-long-enough',
                'key-b' => 'secret-for-key-b-that-is-definitely-long-enough',
            ],
            'path' => ['/api'],
        ]);

        $token = JWT::encode(
            ['sub' => 'user-2', 'exp' => time() + 3600],
            'secret-for-key-b-that-is-definitely-long-enough',
            'HS256',
            'key-b'
        );

        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api/orders')
            ->withHeader('Authorization', 'Bearer ' . $token);

        $response = $middleware->process($request, $this->handler());

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('ok:user-2', (string) $response->getBody());
    }

    public function testCustomErrorCallbackIsInvoked(): void
    {
        $middleware = new JwtAuthMiddleware([
            'secret' => self::SECRET,
            'path' => ['/api'],
            'error' => function (ResponseInterface $response, array $arguments) {
                $response->getBody()->write('custom-error:' . $arguments['message']);
                return $response->withStatus(403);
            },
        ]);

        $request = (new ServerRequestFactory())->createServerRequest('GET', 'https://example.com/api/orders');
        $response = $middleware->process($request, $this->handler());

        $this->assertSame(403, $response->getStatusCode());
        $this->assertStringStartsWith('custom-error:', (string) $response->getBody());
    }
}
