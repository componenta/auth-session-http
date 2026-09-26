# Componenta Auth Session HTTP

Secure browser transport and PSR-15 integration for `componenta/auth-session`.

Active authentication sessions use a non-persistent `__Host-` cookie with
`Secure`, `HttpOnly`, `Path=/` and explicit `SameSite`. Persistent
remember-me credentials belong to the future `componenta/auth-remember-me`
capability package.

This package also owns browser-only session security:

- pre-authentication cookie + request-token binding;
- session assurance middleware;
- activity tracking;
- authentication-session logout/publication;
- CSRF tokens bound to `AuthSession::$uuid + credentialGeneration`.

CSRF lives under `Componenta\Auth\Session\Http\Csrf`; there is no separate
`componenta/auth-session-csrf` package in the Auth 3 architecture.


## Session activity

Idle lifetime is fail-safe. `AuthSessionActivityMiddleware` touches a session
only when the request attribute `SessionActivity::class` equals
`SessionActivity::Interactive`. Unclassified/background requests and 401/403
responses do not extend idle expiry.
