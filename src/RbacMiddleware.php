<?php

declare(strict_types=1);

namespace SlimJwtAuth;

use InvalidArgumentException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use SlimJwtAuth\Support\ResolvesResponseFactory;

/**
 * Role/permission authorization middleware, meant to run *after*
 * JwtAuthMiddleware on a route or group. It reads the decoded claims that
 * JwtAuthMiddleware attached to the request (default attribute "token") and
 * checks them against roles and/or permissions you require for that route.
 *
 *   $app->group('/api/admin', function ($group) {
 *       $group->get('/users', ListUsersAction::class);
 *   })->add(RbacMiddleware::requireRole('admin'));
 *
 *   $app->delete('/api/posts/{id}', DeletePostAction::class)
 *       ->add(new RbacMiddleware([
 *           'permissions' => ['posts.delete'],
 *           'role_permissions' => [
 *               'admin' => ['*'],
 *               'editor' => ['posts.create', 'posts.edit', 'posts.delete'],
 *           ],
 *       ]));
 *
 * Roles are read from a claim (default "roles") that can be a JSON array,
 * or a space/comma separated string (OAuth2-scope style). If you need
 * something custom — nested claims, an external lookup, whatever — pass a
 * "roles_extractor" callable instead.
 */
final class RbacMiddleware implements MiddlewareInterface
{
    use ResolvesResponseFactory;

    private const array DEFAULTS = [
        'attribute' => 'token',
        'roles_claim' => 'roles',
        'roles_extractor' => null,
        'roles' => [],
        'permissions' => [],
        'role_permissions' => [],
        'mode' => 'any',
        'error' => null,
        'response_factory' => null,
    ];

    private readonly array $options;
    private readonly ResponseFactoryInterface $responseFactory;

    public function __construct(array $options = [])
    {
        $this->options = array_replace(self::DEFAULTS, $options);

        if (!in_array($this->options['mode'], ['any', 'all'], true)) {
            throw new InvalidArgumentException('RBAC "mode" option must be either "any" or "all".');
        }

        $this->responseFactory = $this->resolveResponseFactory($this->options['response_factory']);
    }

    /** Require ANY of the given roles (logical OR). */
    public static function requireRole(string ...$roles): self
    {
        return new self(['roles' => $roles, 'mode' => 'any']);
    }

    /** Require ALL of the given roles (logical AND). */
    public static function requireAllRoles(string ...$roles): self
    {
        return new self(['roles' => $roles, 'mode' => 'all']);
    }

    /** Require ANY of the given permissions (logical OR). */
    public static function requirePermission(string ...$permissions): self
    {
        return new self(['permissions' => $permissions, 'mode' => 'any']);
    }

    /** Require ALL of the given permissions (logical AND). */
    public static function requireAllPermissions(string ...$permissions): self
    {
        return new self(['permissions' => $permissions, 'mode' => 'all']);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $claims = $request->getAttribute($this->options['attribute']);

        if ($claims === null) {
            // No decoded token on the request at all — RBAC ran without a
            // preceding auth step (or auth failed and should have already
            // short-circuited). Fail closed with 401, not 403: the caller
            // was never authenticated in the first place.
            return $this->respondWithError($request, 'Not authenticated.', 401, [], []);
        }

        $actualRoles = $this->extractRoles($claims);
        $actualPermissions = $this->resolvePermissions($actualRoles);

        $rolesOk = $this->satisfies($actualRoles, (array) $this->options['roles'], $this->options['mode']);
        $permissionsOk = $this->satisfies($actualPermissions, (array) $this->options['permissions'], $this->options['mode']);

        if (!$rolesOk || !$permissionsOk) {
            return $this->respondWithError($request, 'Insufficient privileges.', 403, $actualRoles, $actualPermissions);
        }

        return $handler->handle($request);
    }

    /** @return string[] */
    private function extractRoles(mixed $claims): array
    {
        if (is_callable($this->options['roles_extractor'])) {
            return array_values(array_map(strval(...), (array) ($this->options['roles_extractor'])($claims)));
        }

        $claimsArray = (array) $claims;
        $value = $claimsArray[$this->options['roles_claim']] ?? [];

        if (is_string($value)) {
            $value = preg_split('/[\s,]+/', trim($value), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        }

        return array_values(array_map(strval(...), (array) $value));
    }

    /**
     * Expands roles into permissions via the "role_permissions" map. A role
     * mapped to "*" grants every permission check for that request.
     *
     * @param string[] $roles
     * @return string[]
     */
    private function resolvePermissions(array $roles): array
    {
        $map = (array) $this->options['role_permissions'];

        if ($map === []) {
            return [];
        }

        $permissions = [];
        foreach ($roles as $role) {
            foreach ((array) ($map[$role] ?? []) as $permission) {
                $permissions[] = (string) $permission;
            }
        }

        return array_values(array_unique($permissions));
    }

    /**
     * @param string[] $actual
     * @param string[] $required
     */
    private function satisfies(array $actual, array $required, string $mode): bool
    {
        if ($required === []) {
            return true;
        }

        if (in_array('*', $actual, true)) {
            return true;
        }

        if ($mode === 'all') {
            return count(array_intersect($required, $actual)) === count(array_unique($required));
        }

        return array_intersect($required, $actual) !== [];
    }

    private function respondWithError(
        ServerRequestInterface $request,
        string $message,
        int $status,
        array $actualRoles,
        array $actualPermissions
    ): ResponseInterface {
        $response = $this->responseFactory->createResponse($status);

        if (is_callable($this->options['error'])) {
            $result = ($this->options['error'])($response, [
                'message' => $message,
                'request' => $request,
                'required_roles' => (array) $this->options['roles'],
                'actual_roles' => $actualRoles,
                'required_permissions' => (array) $this->options['permissions'],
                'actual_permissions' => $actualPermissions,
            ]);

            if ($result instanceof ResponseInterface) {
                return $result;
            }
        }

        $response->getBody()->write(json_encode(['error' => $message], JSON_THROW_ON_ERROR));

        return $response->withHeader('Content-Type', 'application/json');
    }
}
