# simple_keystore

A Python library for encrypted key storage in SQLite with optional Redis-based rate limiting. Designed for development and on-prem use. For production, consider secrets managers or other built-in secure provider methods.

## Features

- **Encrypted storage** -- Keys are encrypted with Fernet symmetric encryption and stored in SQLite with metadata (name, source, login, batch, expiration dates).
- **Rate limiting** -- Optional sliding-window rate limiting per key using Redis and atomic Lua scripts.
- **Key orchestration** -- High-level API that combines storage and throttling with exponential backoff to find and claim an available key.
- **CLI tool** -- Interactive menu-driven interface for managing keys.

## Installation

```bash
pip install simple_keystore
```

Redis is required only if you use the rate limiting features (`SKSRateThrottler`, `get_available_key_for_use`).

## Configuration

Set the encryption key via environment variable (preferred) or `.netrc`:

```bash
export SIMPLE_KEYSTORE_KEY="your-fernet-key"
```

Or add an entry to `~/.netrc`:

```
machine SIMPLE_KEYSTORE_KEY
login unused
password your-fernet-key
```

Generate a valid Fernet key with:

```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```

## Usage

### Key Storage

```python
from simple_keystore import SimpleKeyStore

ks = SimpleKeyStore("my_keys.db")

# Add keys
ks.add_key("openai", "sk-abc123", active=True)
ks.add_key("openai", "sk-def456", active=True, source="vendor-a", batch="2024-q1")

# Retrieve a key by name (raises if more than one match)
key = ks.get_key_by_name("openai")

# Query matching records
records = ks.get_matching_key_records(name="openai", active=True)
for r in records:
    print(r["id"], r["key"], r["usable"])

# Deactivate / reactivate
ks.mark_key_inactive("sk-abc123")
ks.mark_key_active("sk-abc123")

# Smart key selection (soonest-expiring, smallest set)
next_key = ks.get_next_usable_key(name="openai")
```

### Rate Limiting

```python
from datetime import timedelta
from simple_keystore import SKSRateThrottler

# Allow 10 uses per 60-second window
throttler = SKSRateThrottler(
    api_key_id=1,
    number_of_uses_allowed=10,
    amount_of_time=timedelta(seconds=60),
    redis_host="localhost",
    redis_port=6379,
)

# Check remaining uses
remaining, claimed = throttler.remaining_uses(claim_slot=False)

# Claim a slot
remaining, claimed = throttler.remaining_uses(claim_slot=True)

# Target a different key without mutating instance state
remaining, claimed = throttler.remaining_uses(claim_slot=True, api_key_id=42)

# Block until a slot opens (with timeout)
remaining = throttler.wait_until_available(timeout=300, verbose=True)
```

You can also inject a `redis_client` directly (e.g., for testing with `fakeredis`):

```python
throttler = SKSRateThrottler(
    api_key_id=1,
    number_of_uses_allowed=10,
    amount_of_time=timedelta(seconds=60),
    redis_client=my_redis_instance,
)
```

When an external `redis_client` is provided, the throttler will not close it on destruction.

### Combined: Get an Available Key

```python
from simple_keystore import SimpleKeyStore, get_available_key_for_use

ks = SimpleKeyStore("my_keys.db")

key_record, remaining = get_available_key_for_use(
    key_name="openai",
    keystore=ks,
    key_number_of_uses_allowed=10,
    key_use_window_in_seconds=60,
    redis_host="localhost",
    redis_port=6379,
    how_long_to_try_in_seconds=3600,  # retry for up to 1 hour
    max_wait_cap_in_seconds=180.0,    # cap backoff at 3 minutes
)

print(key_record["key"], remaining)
```

This iterates through matching keys, attempts to claim a rate-limit slot for each, and retries with exponential backoff (1.5x multiplier) until one is available or the timeout is reached.

### CLI

```bash
manage_simple_keys my_keys.db
```

Provides an interactive menu for adding, removing, activating/deactivating, and listing keys.

## API Reference

### `SimpleKeyStore(name="simple_keystore.db")`

| Method | Description |
|--------|-------------|
| `add_key(name, unencrypted_key, ...)` | Add a key with optional metadata (active, expiration_in_sse, batch, source, login). Returns the new record id. |
| `get_key_by_name(name)` | Get the decrypted key value by name. Raises if not exactly one match. |
| `get_key_record(unencrypted_key)` | Get the full record dict for a key value. |
| `get_key_record_by_id(id)` | Get the full record dict by id. |
| `get_matching_key_records(...)` | Query records by name, active, batch, source, login, with optional sort_order. |
| `get_next_usable_key(...)` | Smart selection: soonest-expiring within 12h, then smallest set for load balancing. |
| `update_key(id_to_update, ...)` | Update metadata fields on a key record. |
| `mark_key_active(unencrypted_key)` | Mark a key as active. |
| `mark_key_inactive(unencrypted_key)` | Mark a key as inactive. |
| `delete_key_record(unencrypted_key)` | Delete a key record by value. |
| `delete_matching_key_records(...)` | Delete records matching the given filters. |
| `records_for_usability_report(...)` | Get sorted records with optional printed table. |
| `usability_counts_report(...)` | Get per-set counts (total, active, expired, usable). |

### `SKSRateThrottler(api_key_id, number_of_uses_allowed, amount_of_time, ...)`

| Method | Description |
|--------|-------------|
| `remaining_uses(claim_slot=False, api_key_id=None)` | Check remaining uses and optionally claim a slot. Returns `(remaining, slot_claimed)`. Pass `api_key_id` to target a different rate bucket. |
| `wait_until_available(timeout=7200, verbose=False, api_key_id=None, sleep_func=None, clock_func=None)` | Block until a slot is claimed. Raises `TimeoutError` on timeout. Accepts injectable `sleep_func`/`clock_func` for testing. |

### `get_available_key_for_use(key_name, keystore, ...)`

Finds and claims an available key matching `key_name` with rate limiting. Returns `(key_record, remaining_uses)`. Retries with exponential backoff.

### `get_key_with_most_uses_remaining(key_name, keystore, verbose=False)`

Returns the id of the key with the most remaining rate-limit uses, or `None`.

## License

MIT
