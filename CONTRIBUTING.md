# Contributing

## Development Setup

There is a `.devcontainer` and `Dockerfile` included for use with VS Code / GitHub Codespaces.

### Prerequisites

- Python 3.10+
- Redis (only needed for rate throttling features and integration tests)

```bash
sudo apt-get install -y redis-server
sudo service redis-server start
```

### Install Dependencies

```bash
pip install -e .
```

### Set Encryption Key

```bash
export SIMPLE_KEYSTORE_KEY="your-fernet-key"
```

## Commands

```bash
# Run all unit tests
pytest tests/

# Run specific test file
pytest tests/test_simple_keystore.py

# Run a single test by name
pytest tests/test_simple_keystore.py -k "test_function_name"

# Lint
ruff check src/

# Format
ruff format src/

# Type checking
pyright

# CLI tool
manage_simple_keys <KEYSTORE_FILE_NAME>
```

### Integration Tests

The `scripts/` directory contains integration tests that require a running Redis server. They are picked up by `pytest` when run from the repo root but are not part of the core test suite:

```bash
# Run only unit tests (no Redis required)
pytest tests/

# Run everything including integration tests (Redis required)
pytest
```

## Architecture

The codebase has four layers:

1. **Storage layer** (`simple_keystore.py`) -- SQLite + Fernet symmetric encryption. The encryption key comes from the `SIMPLE_KEYSTORE_KEY` env var (priority) or a `.netrc` password entry. Each call to `encrypt` produces different ciphertext, so key comparison requires decryption.

2. **Throttling layer** (`sks_rate_throttler.py`) -- Redis sorted sets with an atomic Lua script for sliding-window rate limiting. Each API key gets its own Redis key (`ratelimit:{api_key_id}`). The Lua script atomically removes expired entries, counts current usage, and optionally claims a slot in one round-trip. The Lua script is a class-level constant (`_LUA_SCRIPT`), loaded into Redis once per instance. The throttler tracks whether it owns the Redis connection and only closes it on destruction if it created the connection itself.

3. **Orchestration layer** (`get_available_key_for_use.py`) -- Ties storage + throttling together with exponential backoff retry (1.5x multiplier, capped by `max_wait_cap_in_seconds`). A single `SKSRateThrottler` instance is reused across all keys in a query, with `api_key_id` passed per-call to `remaining_uses()`.

4. **CLI layer** (`manage_simple_keys.py`) -- Interactive menu-driven key management.

### Key Selection Logic

Keys are grouped into "sets" by four set-defining fields: `name`, `source`, `login`, `batch`. When selecting a key, the system prefers soonest-expiring keys (within a 12-hour window) and breaks ties by choosing from the smallest key set for load balancing.

### SQLite Schema

The `keystore` table stores: `id`, `name`, `expiration_in_sse` (Unix timestamp), `active` (0/1), `batch`, `source`, `login`, `encrypted_key` (UNIQUE), `created_at`, `updated_at`. Records expose computed properties: `expired`, `usable` (active AND not expired), and `key` (decrypted value).

## Testing

- Tests use `fakeredis.FakeStrictRedis` for Redis (no real Redis needed)
- Tests use `freezegun` for time-dependent behavior
- Rate throttler tests monkeypatch Lua script execution
- `wait_until_available` tests use injectable `clock_func`/`sleep_func` to avoid real sleeps
- `tests/keystore_for_tests.db` is a pre-created SQLite database used by tests
- pytest `pythonpath` is configured to include `src/` in `pyproject.toml`

## Code Style

- Line length: 120 characters (configured in `pyproject.toml`)
- Uses ruff for linting/formatting with isort `combine-as-imports`
- Python 3.10+ required
- All SQL queries use parameterized placeholders (no string interpolation)
