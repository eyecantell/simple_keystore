# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**simple_keystore** is a Python library for encrypted key storage in SQLite with optional Redis-based rate limiting. It provides:
- `SimpleKeyStore` - Core encrypted key storage with metadata (name, source, login, batch, expiration dates)
- `SKSRateThrottler` - Redis-based rate limiting using Lua scripts for atomic operations
- `get_available_key_for_use()` - High-level API combining storage + throttling with exponential backoff
- `manage_simple_keys` - Interactive CLI for key management

## Commands

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_simple_keystore.py

# Lint and format
ruff check src/
ruff format src/

# Type checking
pyright

# CLI tool
manage_simple_keys <KEYSTORE_FILE_NAME>
```

## Architecture

```
src/simple_keystore/
├── simple_keystore.py          # Core: SQLite + Fernet encryption
├── sks_rate_throttler.py       # Rate limiting with Redis Lua scripts
├── get_available_key_for_use.py  # High-level API integrating both
├── get_key_with_most_uses_remaining.py  # Utility for key selection
└── manage_simple_keys.py       # Interactive CLI entry point
```

**Key Flow:** `get_available_key_for_use()` queries `SimpleKeyStore` for matching keys, then uses `SKSRateThrottler` to find one within rate limits, with configurable retry/backoff behavior.

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
