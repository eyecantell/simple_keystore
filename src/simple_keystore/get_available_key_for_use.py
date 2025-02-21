from simple_keystore import SimpleKeyStore, SKSRateThrottler
from datetime import timedelta
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 3600


def get_available_key_for_use(
    key_name: str,
    keystore: SimpleKeyStore,
    key_number_of_uses_allowed: int,
    key_use_window_in_seconds: int,
    redis_host: str,
    redis_port: int,
    how_long_to_try_in_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    verbose: bool = False,
) -> str:
    """Returns the first available key string matching key_name that is active, not expired, and has usage slots available.

    Args:
        key_name: The name of the key to search for.
        keystore: The SimpleKeyStore instance to query.
        key_number_of_uses_allowed: Maximum uses allowed per key in the time window.
        key_use_window_in_seconds: Time window in seconds for usage limits.
        redis_host: Redis hostname for rate limiting.
        redis_port: Redis port for rate limiting.
        how_long_to_try_in_seconds: Maximum time to retry before giving up (default: 3600).
        verbose: Whether to log debug information (default: False).

    Returns:
        str: The key string ready for use.

    Raises:
        TimeoutError: If no key is available after how_long_to_try_in_seconds.
        ConnectionError: If Redis or keystore connection fails.
        Exception: For other unexpected errors.
    """
    throttler = SKSRateThrottler(
        api_key_id=0,  # Temporary ID, updated per key
        number_of_uses_allowed=key_number_of_uses_allowed,
        amount_of_time=timedelta(seconds=key_use_window_in_seconds),
        redis_host=redis_host,
        redis_port=redis_port,
    )

    start_time = time.time()
    wait_time_in_seconds = 1.0

    while True:
        try:
            key_record_to_use = _attempt_to_grab_a_slot_from_available_keys(
                key_name=key_name, keystore=keystore, throttler=throttler, verbose=verbose
            )
            if key_record_to_use:
                if verbose:
                    logger.debug(f"Found available key: {key_record_to_use}")
                return key_record_to_use["key"]

            elapsed = time.time() - start_time
            if elapsed >= how_long_to_try_in_seconds:
                raise TimeoutError(f"No {key_name} keys available after {how_long_to_try_in_seconds}s")

            if verbose:
                logger.debug(f"No keys available. Retrying in {wait_time_in_seconds:.1f}s")
            time.sleep(min(wait_time_in_seconds, 180))
            wait_time_in_seconds *= 1.5

        except TimeoutError:
            raise
        except ConnectionError as e:
            if verbose:
                logger.error(f"Connection error: {str(e)}")
            raise
        except Exception as e:
            if verbose:
                logger.error(f"Unexpected error: {str(e)}")
            raise


def _attempt_to_grab_a_slot_from_available_keys(
    key_name: str, keystore: SimpleKeyStore, throttler: SKSRateThrottler, verbose: bool = False
) -> Optional[dict]:
    """Attempts to claim a usage slot for a key from the keystore. Returns the first successful key record or None."""
    matching_records = keystore.get_matching_key_records(name=key_name, active=True)

    for key_record in matching_records:
        if not key_record["usable"]:
            continue

        throttler.api_key_id = key_record["id"]
        remaining, slot_claimed = throttler.remaining_uses(claim_slot=True)

        if slot_claimed:
            if verbose:
                logger.debug(f"Claimed slot for key {key_name} id {key_record['id']} ({remaining} uses left)")
            return key_record
        elif verbose:
            logger.debug(f"Key {key_name} id {key_record['id']} has {remaining} uses left - trying next")

    return None
