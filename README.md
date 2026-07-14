# apigopro/slim-jwt-auth

A PSR-15 JWT authentication middleware for **Slim Framework 4**, requiring **PHP 8.5**.

It's a spiritual successor to [`tuupola/slim-jwt-auth`](https://github.com/tuupola/slim-jwt-auth)
(unmaintained since 2022) — same array-based options, same `path`/`ignore`/`before`/`after`/`error`
callback shape — but built directly on [`firebase/php-jwt`](https://github.com/firebase/php-jwt) 7.x,
since tuupola's package depended on firebase/php-jwt's old (pre-6.0) API that no longer exists.

## Install

This package isn't published on Packagist — install it as a VCS repository pointing at wherever
you host the git repo (GitHub, GitLab, a private server, etc.).

In your app's `composer.json`:

```json
{
    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/your-org/slim-jwt-auth.git"
        }
    ],
    "require": {
        "apigopro/slim-jwt-auth": "^1.0",
        "slim/psr7": "^1.7"
    }
}
```

Then:

```bash
composer update apigopro/slim-jwt-auth
```

`^1.0` resolves against the `v1.0.0` tag in the repo. If you push new commits without tagging a new
release, require `dev-main` instead until you're ready to cut `v1.0.1`, etc.

## Basic usage

```php
use SlimJwtAuth\JwtAuthMiddleware;

$app->add(new JwtAuthMiddleware([
    'secret' => 'supersecretkeyyoushouldnotcommittogithub',
    'path'   => ['/api'],          // only these paths require a token
    'ignore' => ['/api/login'],    // except these
]));

$app->get('/api/me', function ($request, $response) {
    $claims = $request->getAttribute('token'); // decoded JWT payload (stdClass)
    $response->getBody()->write($claims->sub);
    return $response;
});
```

Requests are authenticated by reading `Authorization: Bearer <token>` (configurable), decoding it
with `firebase/php-jwt`, and — on success — attaching the decoded claims to the request as an
attribute (`token` by default) before your route handler runs. Anything that fails verification
(bad signature, expired, wrong audience if you check it yourself, etc.) short-circuits with a
JSON `401`.

## Options

| Option             | Default                          | Notes |
|---------------------|-----------------------------------|-------|
| `secret`            | *(required)*                      | String, or `['kid' => secret]` map for key rotation, or `['kid' => [secret, algorithm]]` for per-key algorithms. |
| `algorithm`          | `'HS256'`                          | Used for `secret` values that don't specify their own algorithm. |
| `header`             | `'Authorization'`                  | Header to read the token from. |
| `regexp`             | `/Bearer\s+(.*)$/i`                 | Pattern used to pull the token out of the header. |
| `cookie`             | `'token'`                          | Cookie name used as a fallback if the header is absent. Set to `false` to disable. |
| `attribute`          | `'token'`                          | Request attribute the decoded claims are stored under. Set to `false` to skip attaching. |
| `path`               | `['/']`                            | Path prefixes that require authentication. `'/api'` matches `/api`, `/api/x`, `/api/x/y`, etc. Supports `*` wildcards, e.g. `'/api/*/public'`. |
| `ignore`             | `[]`                               | Path prefixes exempted from authentication, checked before `path`. |
| `before`             | `null`                             | `function($request, array $claims): ?ServerRequestInterface` — run after successful auth, before the route handler. Return a modified request to replace it. |
| `after`              | `null`                             | `function($response, array $claims): ?ResponseInterface` — run after the route handler. Return a modified response to replace it. |
| `error`              | `null`                             | `function($response, array $arguments): ?ResponseInterface` — called on auth failure. `$arguments['message']` has the reason. Return a response to override the default JSON 401/400. |
| `secure`             | `true`                             | Require HTTPS (or a `relaxed` host) unless `false`. |
| `relaxed`            | `['localhost', '127.0.0.1']`        | Hostnames allowed over plain HTTP even when `secure` is `true`. |
| `leeway`             | `0`                                | Seconds of clock skew tolerance for `exp`/`nbf`/`iat` checks (maps to `Firebase\JWT\JWT::$leeway`). |
| `rules`              | *(auto)*                          | Advanced: pass your own array of `SlimJwtAuth\RuleInterface` implementations to fully control which requests get authenticated, replacing the default path/method rules. |
| `response_factory`   | *(auto-detects `slim/psr7`)*        | Any PSR-17 `ResponseFactoryInterface`. Only needed if you're not using `slim/psr7`. |

## Key rotation / multiple keys

```php
new JwtAuthMiddleware([
    'secret' => [
        '2026-01' => 'old-key-still-valid-for-existing-tokens',
        '2026-07' => 'current-signing-key',
    ],
    'algorithm' => 'HS256',
]);
```

The middleware picks the right key by matching the token's `kid` header against the array keys —
this is the same mechanism `firebase/php-jwt` uses natively, just wired up for you.

## Role-based access control (RBAC)

`RbacMiddleware` runs *after* `JwtAuthMiddleware` (usually attached per-route or per-group) and
checks roles/permissions found in the decoded claims that `JwtAuthMiddleware` already attached
to the request.

```php
use SlimJwtAuth\JwtAuthMiddleware;
use SlimJwtAuth\RbacMiddleware;

$app->add(new JwtAuthMiddleware(['secret' => $secret, 'path' => ['/api']]));

// Only "admin" (or any role you list) may hit this group.
$app->group('/api/admin', function ($group) {
    $group->get('/users', ListUsersAction::class);
})->add(RbacMiddleware::requireRole('admin'));
```

Slim runs middleware innermost-first for a route, so attach `JwtAuthMiddleware` at the app level
(or earlier in the stack) and `RbacMiddleware` on the specific route/group that needs it.

### Roles claim

By default, roles come from a `roles` claim in the JWT, which can be:

- a JSON array: `{"roles": ["admin", "editor"]}`
- a comma-separated string: `{"roles": "admin, editor"}`
- a space-separated string (OAuth2 `scope`-style): `{"roles": "admin editor"}`

Change the claim name with `'roles_claim' => 'scope'`, or supply `'roles_extractor' => fn($claims) => [...]`
for anything more custom (nested claims, an external lookup, etc.) — it receives the full decoded
claims object and must return a plain array of role strings.

### Permissions

For finer-grained checks than "has this role", map roles to permissions and require permissions
instead of (or alongside) roles:

```php
new RbacMiddleware([
    'permissions' => ['posts.delete'],
    'role_permissions' => [
        'admin'  => ['*'],                         // "*" grants every permission
        'editor' => ['posts.create', 'posts.edit'],
    ],
]);
```

### Static constructors

```php
RbacMiddleware::requireRole('admin', 'editor');        // any of these roles
RbacMiddleware::requireAllRoles('admin', 'billing');    // all of these roles
RbacMiddleware::requirePermission('posts.delete');      // any of these permissions
RbacMiddleware::requireAllPermissions('posts.delete', 'posts.publish');
```

For anything the static constructors don't cover, use the array-options form directly — it accepts
everything below.

### RBAC options

| Option              | Default        | Notes |
|----------------------|-----------------|-------|
| `attribute`          | `'token'`        | Same attribute name `JwtAuthMiddleware` writes decoded claims to. |
| `roles_claim`        | `'roles'`        | Claim to read roles from. |
| `roles_extractor`    | `null`           | `function($claims): string[]` — overrides `roles_claim` entirely. |
| `roles`              | `[]`             | Required roles. Empty means "no role requirement". |
| `permissions`        | `[]`             | Required permissions. Empty means "no permission requirement". |
| `role_permissions`   | `[]`             | `['role' => ['permission', ...]]` map. `'*'` grants all permissions for that role. |
| `mode`               | `'any'`          | `'any'` (OR) or `'all'` (AND), applied independently to `roles` and `permissions`. |
| `error`              | `null`           | `function($response, array $arguments): ?ResponseInterface`. `$arguments` has `message`, `request`, `required_roles`, `actual_roles`, `required_permissions`, `actual_permissions`. |
| `response_factory`   | *(auto-detects `slim/psr7`)* | Same as `JwtAuthMiddleware`. |

### Status codes

- **401** if there's no decoded token on the request at all (RBAC ran without a preceding
  successful auth step — this is a configuration issue, not "wrong role").
- **403** if the caller is authenticated but lacks the required role(s) or permission(s).



## Migrating from tuupola/slim-jwt-auth

Most configs port over unchanged. Concrete differences:

- **Namespace**: `Tuupola\Middleware\JwtAuthentication` → `SlimJwtAuth\JwtAuthMiddleware`.
- **`secret` is stricter about key length.** firebase/php-jwt 7.x rejects HMAC secrets shorter than
  the algorithm's bit strength (32+ bytes for HS256). If you were using a short secret, generate a
  longer one — this was always weak, just previously unenforced.
- **No `secure` bypass for `null` scheme by accident.** If you test with bare-path PSR-7 requests
  that have no scheme/host set, `secure` will (correctly) reject them as insecure. Real requests
  from a web server always carry a scheme/host, so this only affects hand-rolled test fixtures.
- **`error` callback signature** takes `(ResponseInterface $response, array $arguments)`, same as
  before, but `$arguments['request']` is now the actual `ServerRequestInterface`, not a decoded
  info array — adjust if you were reading `$arguments['uri']` etc.
- **No built-in JWKS/remote-key fetching.** Firebase's JWT library supports it separately; wire it
  up yourself and pass the resolved key(s) via `secret` if you need that.

## Testing

```bash
composer install
composer test
```

The test suite covers: valid tokens, missing/expired/mis-signed tokens, `path`/`ignore` prefix
matching, `kid`-based key rotation, custom `error` callbacks, cookie fallback, the `secure`/`relaxed`
HTTPS enforcement, `before`/`after` hooks, and RBAC role/permission checks (any/all modes, wildcard
permissions, custom role extraction, and the 401-vs-403 distinction).

## License

MIT.
