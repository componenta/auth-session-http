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

The package requires `componenta/http-csrf-middleware ^3.0`. Unsafe browser
requests therefore follow the CSRF v3 trust model: Fetch Metadata is used as
defense in depth, Origin/Referer is verified, and the token is bound to the
authoritative authentication session. Middleware integration relies on the
guarded handler being invoked, not on PSR-7 response object identity, so
response decoration such as `Vary` does not turn an accepted request into a
false rejection.

## Session grant publication

`AuthSessionGrantPublisher` validates that a grant is current before publishing
it. Without a `CredentialTransportState` request attribute, it stores the
credential immediately and applies the response's non-caching headers.

When authentication middleware already owns a transport state, the publisher
queues the grant and its failure compensation in that state and returns the
unchanged response. The owning middleware publishes the queue after downstream
handling. This preserves publication order when a restored session is
reauthenticated in the same request: the newer generation supplies the final
cookie. A publication failure or terminal clear revokes an unpublished grant.

## Session activity

Idle lifetime is fail-safe. `AuthSessionActivityMiddleware` touches a session
only when the request attribute `SessionActivity::class` equals
`SessionActivity::Interactive`. Unclassified/background requests and 401/403
responses do not extend idle expiry.
