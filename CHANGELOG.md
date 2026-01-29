# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.11.0] - 2025-01-29

### Added
- GitHub Actions CI workflow with lint (ruff) and test (pytest) jobs across Python 3.10–3.13.
- `pdm.lock` now includes the `test` dependency group.

## [0.10.0] - 2025-01-29

### Added
- `remaining_uses()` and `wait_until_available()` accept an optional `api_key_id` parameter to target different rate buckets without mutating instance state.
- `wait_until_available()` accepts injectable `sleep_func` and `clock_func` for testing without real sleeps.
- `SKSRateThrottler` tracks Redis connection ownership -- injected clients are no longer closed on destruction.
- Read-only `redis` property and read/write `api_key_id` property on `SKSRateThrottler` for backward-compatible access.
- New unit tests for connection ownership, per-call `api_key_id`, timeout, backoff, and verbose output.
- `CONTRIBUTING.md` with development setup, architecture, testing, and code style.
- `get_key_with_most_uses_remaining()` accepts optional `throttler` parameter for reusing rate limiters.
- PyPI classifiers for package discoverability.

### Changed
- `README.md` rewritten as user-facing documentation with usage examples and API reference.
- `CLAUDE.md` updated to reflect refactored internals.
- Lua script promoted from `__init__` local to `_LUA_SCRIPT` class variable.
- Internal attributes renamed: `self.redis` to `self._redis`, `self.api_key_id` to `self._default_api_key_id`, `self.lua_increment_script_sha` to `self._lua_script_sha`.
- `get_available_key_for_use()` passes `api_key_id` per-call instead of mutating `throttler.api_key_id`.
- `get_key_with_most_uses_remaining()` reads key id from the record directly instead of from the throttler.

### Fixed
- `remaining_uses()` now raises `RuntimeError` (not bare `Exception`) with chained cause (`from e`).
- `UnboundLocalError` in `tabulate_records()` when `show_full_key=False` and key length exceeds 20 characters.
- Removed unused `timedelta` import from `simple_keystore.py`.
- Added `*.db` to `.gitignore` for temporary database files.

## [0.9.0] - 2025-01-22

### Added
- "Remove all expired keys" option in `manage_simple_keys` CLI.
- `CLAUDE.md` for Claude Code guidance.

### Changed
- Devcontainer switched to Docker volume for better performance.

## [0.8.0] - 2024-12-18

### Added
- `max_wait_cap_in_seconds` parameter to `get_available_key_for_use()` to cap exponential backoff.

## [0.7.0] - 2024-12-17

### Changed
- `get_available_key_for_use()` now returns `(key_record, remaining_uses)` tuple instead of just the key string.

## [0.6.1] - 2024-12-16

### Fixed
- Removed debugging error log from `get_available_key_for_use`.

## [0.6.0] - 2024-12-16

### Added
- `get_available_key_for_use()` -- high-level API combining keystore queries with rate-limited key selection and exponential backoff retry.

## [0.5.0] - 2024-12-15

### Added
- `get_key_with_most_uses_remaining()` utility function.

## [0.4.0] - 2024-12-14

### Changed
- `remaining_uses()` now returns remaining count alongside the claimed flag.
- Added Redis integration test for throttler.

## [0.3.2] - 2024-12-13

### Fixed
- Fixed path to `manage_simple_keys` CLI entry point.

## [0.3.1] - 2024-12-13

### Changed
- Rate throttler moved to atomic Lua script execution for sliding-window rate limiting.

## [0.3.0] and earlier

Initial development: encrypted key storage in SQLite with Fernet, interactive CLI (`manage_simple_keys`), key metadata (name, source, login, batch, expiration), Redis-based rate tracking, and foundational test suite.
