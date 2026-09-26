# Componenta Auth Session HTTP

Secure browser transport and PSR-15 integration for `componenta/auth-session`.

Active authentication sessions use a non-persistent `__Host-` cookie with
`Secure`, `HttpOnly`, `Path=/` and explicit `SameSite`. Persistent
remember-me credentials belong to `componenta/auth-remember-me-http`.
