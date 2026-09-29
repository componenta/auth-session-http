# Changelog

## v2.0.0

Breaking coordinated release for the CSRF v3 browser security contract.

### Security
- Requires `componenta/http-csrf-middleware ^3.0`.
- Factor-management browser requests now follow the CSRF v3 fail-closed Origin/Referer model.
- Missing source-origin metadata on unsafe factor-management requests is rejected instead of silently accepted.
- Auth-session CSRF key and session identity are redacted from debug output.

### Compatibility
- The `dev-main` branch alias is now `2.0.x-dev`.
- Requires `psr/http-factory ^1.1`.
- Test PSR-7 implementation floor is `nyholm/psr7 ^1.8.2`.
- Applications must send browser Origin/Referer metadata for unsafe CSRF-protected requests or explicitly configure compatibility behavior in the underlying CSRF middleware where appropriate.

### Testing
- PHPStan level max now covers both `src` and `tests`.
- Test anti-patterns were removed: tautological assertions were replaced with contract assertions and input variations use data providers.
- CI passes on PHP 8.4 and 8.5 against the released CSRF v3 dependency.
