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
use SlimJwtAuth\RbacMiddleware;

final class RbacMiddlewareTest extends TestCase
{
    private const SECRET = 'super-secret-test-key-thats-long-enough';

    private function okHandler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $response = (new ResponseFactory())->createResponse(200);
                $response->getBody()->write('ok');
                return $response;
            }
        };
    }

    /**
     * Runs the real JwtAuthMiddleware first so the RBAC middleware sees
     * exactly what it would see in a real Slim app: a "token" attribute
     * holding the decoded claims.
     */
    private function requestWithClaims(array $claims): ServerRequestInterface
    {
        $token = JWT::encode(array_merge(['sub' => 'user-1', 'exp' => time() + 3600], $claims), self::SECRET, 'HS256');
        $jwtMiddleware = new JwtAuthMiddleware(['secret' => self::SECRET, 'path' => ['/api']]);

        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api/orders')
            ->withHeader('Authorization', 'Bearer ' . $token);

        $captured = null;
        $jwtMiddleware->process($request, new class ($captured) implements RequestHandlerInterface {
            public function __construct(private mixed &$captured)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->captured = $request;
                return (new ResponseFactory())->createResponse(200);
            }
        });

        return $captured;
    }

    public function testRequiredRolePresentIsAllowed(): void
    {
        $request = $this->requestWithClaims(['roles' => ['admin', 'editor']]);
        $response = RbacMiddleware::requireRole('admin')->process($request, $this->okHandler());

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testMissingRequiredRoleIsForbidden(): void
    {
        $request = $this->requestWithClaims(['roles' => ['viewer']]);
        $response = RbacMiddleware::requireRole('admin')->process($request, $this->okHandler());

        $this->assertSame(403, $response->getStatusCode());
    }

    public function testNoAuthenticationYieldsUnauthorizedNotForbidden(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('GET', 'https://example.com/api/orders');
        $response = RbacMiddleware::requireRole('admin')->process($request, $this->okHandler());

        $this->assertSame(401, $response->getStatusCode());
    }

    public function testCommaSeparatedRolesClaimIsParsed(): void
    {
        $request = $this->requestWithClaims(['roles' => 'admin, editor']);
        $response = RbacMiddleware::requireRole('editor')->process($request, $this->okHandler());

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testRequireAllRolesNeedsEveryRole(): void
    {
        $request = $this->requestWithClaims(['roles' => ['admin']]);
        $response = RbacMiddleware::requireAllRoles('admin', 'billing')->process($request, $this->okHandler());

        $this->assertSame(403, $response->getStatusCode());
    }

    public function testRolePermissionMapGrantsExpectedPermission(): void
    {
        $request = $this->requestWithClaims(['roles' => ['editor']]);
        $rbac = new RbacMiddleware([
            'permissions' => ['posts.delete'],
            'role_permissions' => [
                'admin' => ['*'],
                'editor' => ['posts.create', 'posts.edit'],
            ],
        ]);

        $response = $rbac->process($request, $this->okHandler());

        $this->assertSame(403, $response->getStatusCode());
    }

    public function testWildcardRolePermissionGrantsEverything(): void
    {
        $request = $this->requestWithClaims(['roles' => ['admin']]);
        $rbac = new RbacMiddleware([
            'permissions' => ['posts.delete'],
            'role_permissions' => [
                'admin' => ['*'],
                'editor' => ['posts.create', 'posts.edit'],
            ],
        ]);

        $response = $rbac->process($request, $this->okHandler());

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testCustomRolesExtractorIsUsed(): void
    {
        $request = $this->requestWithClaims(['perm' => ['nested' => ['role' => 'super-admin']]]);
        $rbac = new RbacMiddleware([
            'roles' => ['super-admin'],
            'roles_extractor' => fn ($claims) => [$claims->perm->nested->role],
        ]);

        $response = $rbac->process($request, $this->okHandler());

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testCustomErrorCallbackOverridesDefaultResponse(): void
    {
        $request = $this->requestWithClaims(['roles' => ['viewer']]);
        $rbac = new RbacMiddleware([
            'roles' => ['admin'],
            'error' => function (ResponseInterface $response, array $arguments) {
                $response->getBody()->write('custom-forbidden:' . implode(',', $arguments['actual_roles']));
                return $response->withStatus(451);
            },
        ]);

        $response = $rbac->process($request, $this->okHandler());

        $this->assertSame(451, $response->getStatusCode());
        $this->assertSame('custom-forbidden:viewer', (string) $response->getBody());
    }

    public function testNoRequirementsAlwaysPassesForAuthenticatedRequest(): void
    {
        $request = $this->requestWithClaims(['roles' => []]);
        $response = (new RbacMiddleware([]))->process($request, $this->okHandler());

        $this->assertSame(200, $response->getStatusCode());
    }
}
