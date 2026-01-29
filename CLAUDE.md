# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**simple_keystore** is a Python library for encrypted key storage in SQLite with optional Redis-based rate limiting. It provides:
- `SimpleKeyStore` - Core encrypted key storage with metadata (name, source, login, batch, expiration dates)
- `SKSRateThrottler` - Redis-based rate limiting using a Lua script (class-level `_LUA_SCRIPT`) for atomic sliding-window operations
- `get_available_key_for_use()` - High-level API combining storage + throttling with exponential backoff
- `get_key_with_most_uses_remaining()` - Utility to find the least-loaded key (accepts optional `throttler` for reuse)
- `manage_simple_keys` - Interactive CLI for key management

## Commands

```bash
# Run unit tests (no Redis required)
pytest tests/

# Run all tests including integration tests (Redis required)
pytest

# Run specific test file
pytest tests/test_simple_keystore.py

# Run a single test by name
pytest tests/test_simple_keystore.py -k "test_function_name"

# Lint and format
ruff check src/
ruff format src/

# Type checking
pyright

# CLI tool
manage_simple_keys <KEYSTORE_FILE_NAME>
```

## Architecture

The codebase has four layers with clear separation of concerns:

1. **Storage layer** (`simple_keystore.py`) - SQLite + Fernet symmetric encryption. Encryption key comes from `SIMPLE_KEYSTORE_KEY` env var (priority) or `.netrc` password entry. Each call to `encrypt` produces different ciphertext, so key comparison requires decryption.

2. **Throttling layer** (`sks_rate_throttler.py`) - Redis sorted sets with an atomic Lua script for sliding-window rate limiting. Each API key gets its own Redis key (`ratelimit:{api_key_id}`). The Lua script is a class-level constant (`_LUA_SCRIPT`), loaded into Redis once per `__init__`. The throttler tracks connection ownership (`_owns_redis`) and only closes Redis on destruction if it created the connection. Internal state uses `_redis`, `_default_api_key_id`, and `_lua_script_sha` with public properties for backward-compatible access.

3. **Orchestration layer** (`get_available_key_for_use.py`) - Ties storage + throttling together with exponential backoff retry (1.5x multiplier, capped by `max_wait_cap_in_seconds`). A single `SKSRateThrottler` instance is reused across all keys in a query, with `api_key_id` passed per-call to `remaining_uses()`.

4. **CLI layer** (`manage_simple_keys.py`) - Interactive menu-driven key management.

### Key Design Details

- `remaining_uses(claim_slot, api_key_id=None)` and `wait_until_available(..., api_key_id=None)` accept an optional `api_key_id` override so callers can target different rate buckets without mutating instance state.
- `wait_until_available` accepts optional `sleep_func` and `clock_func` callables for testability (avoids real sleeps in tests).
- `remaining_uses` raises `RuntimeError` (not bare `Exception`) with chained cause (`from e`).

### Key Selection Logic

Keys are grouped into "sets" by four **set-defining fields**: `name`, `source`, `login`, `batch`. When selecting a key, the system prefers soonest-expiring keys (within a 12-hour window) and breaks ties by choosing from the smallest key set for load balancing.

### SQLite Schema

The `keystore` table stores: `id`, `name`, `expiration_in_sse` (Unix timestamp), `active` (0/1), `batch`, `source`, `login`, `encrypted_key` (UNIQUE), `created_at`, `updated_at`. Records expose computed properties: `expired`, `usable` (active AND not expired), and `key` (decrypted value).

## Testing

- Tests use `fakeredis.FakeStrictRedis` for Redis (no real Redis needed)
- Tests use `freezegun` for time-dependent behavior
- Rate throttler tests monkeypatch Lua script execution
- `wait_until_available` tests inject `clock_func`/`sleep_func` to avoid real sleeps
- `tests/keystore_for_tests.db` is a pre-created SQLite database used by tests
- `scripts/` contains integration tests requiring a live Redis server
- pytest `pythonpath` is configured to include `src/` in pyproject.toml

## Environment Setup

Set encryption key via environment variable or .netrc:
```bash
export SIMPLE_KEYSTORE_KEY="<encryption-key-phrase>"
```

Redis is required only for rate throttling features (`SKSRateThrottler`, `get_available_key_for_use`).

## Code Style

- Line length: 120 characters (configured in pyproject.toml)
- Uses ruff for linting/formatting with isort combine-as-imports
- Python 3.10+ required
- All SQL queries use parameterized placeholders (no string interpolation)
