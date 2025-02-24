from datetime import timedelta
import time
import logging
from simple_keystore import SimpleKeyStore, SKSRateThrottler
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

def get_available_key_for_use(
    key_name: str,
    keystore: SimpleKeyStore,
    key_number_of_uses_allowed: int,
    key_use_window_in_seconds: int,
    redis_host: str,
    redis_port: int,
    how_long_to_try_in_seconds: int = 3600,
    max_wait_cap_in_seconds: float = 180.0,
) -> Tuple[dict, int]:
    """Returns the dict for the first available key string matching key_name that is active, not expired, 
    and has usage slots available. Also returns the number of uses remaining for the key.

    Args:
        key_name: The name of the key to search for.
        keystore: The SimpleKeyStore instance to query.
        key_number_of_uses_allowed: Maximum uses allowed per key in the time window.
        key_use_window_in_seconds: Time window in seconds for usage limits.
        redis_host: Redis hostname for rate limiting.
        redis_port: Redis port for rate limiting.
        how_long_to_try_in_seconds: Maximum time to retry before giving up (default: 3600).
        max_wait_cap_in_seconds: Maximum time to wait between retries (default: 180.0).

    Returns:
        Tuple[dict, int]: The key record dictionary and the number of uses remaining.

    Raises:
        TimeoutError: If no key is available after how_long_to_try_in_seconds.
        ConnectionError: If Redis or keystore connection fails.
        ValueError: If invalid parameters are provided.
        Exception: For other unexpected errors.
    """
    # Input validation
    if how_long_to_try_in_seconds <= 0 or max_wait_cap_in_seconds <= 0:
        raise ValueError("Time parameters must be positive")
    if not key_name or not isinstance(key_name, str):
        raise ValueError("key_name must be a non-empty string")

    throttler = SKSRateThrottler(
        api_key_id=0,  # Temporary ID, updated per key
        number_of_uses_allowed=key_number_of_uses_allowed,
        amount_of_time=timedelta(seconds=key_use_window_in_seconds),
        redis_host=redis_host,
        redis_port=redis_port,
    )

    start_time = time.time()
    wait_time_in_seconds = 1.0
    attempt_count = 0

    while True:
        try:
            attempt_count += 1
            key_record_to_use, remaining_uses = _attempt_to_grab_a_slot_from_available_keys(
                key_name=key_name, keystore=keystore, throttler=throttler
            )
            
            if key_record_to_use:
                logger.debug(f"Found available key after {attempt_count} attempts: {key_record_to_use}")
                return (key_record_to_use, remaining_uses)

            elapsed = time.time() - start_time
            if elapsed >= how_long_to_try_in_seconds:
                logger.error(f"No {key_name} keys available after {how_long_to_try_in_seconds}s and {attempt_count} attempts")
                raise TimeoutError(f"No {key_name} keys available after {how_long_to_try_in_seconds}s")

            # Calculate actual wait time with cap
            actual_wait = min(wait_time_in_seconds, max_wait_cap_in_seconds)
            logger.info(f"No keys available on attempt {attempt_count}. Retrying in {actual_wait:.1f}s (elapsed: {elapsed:.1f}s)")
            time.sleep(actual_wait)
            
            # Exponential backoff with cap
            wait_time_in_seconds = min(wait_time_in_seconds * 1.5, max_wait_cap_in_seconds)

        except TimeoutError:
            raise
        except ConnectionError as e:
            logger.error(f"Connection error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error on attempt {attempt_count}: {str(e)}")
            raise

def _attempt_to_grab_a_slot_from_available_keys(
    key_name: str, 
    keystore: SimpleKeyStore, 
    throttler: SKSRateThrottler
) -> Tuple[Optional[dict], Optional[int]]:
    """Attempts to claim a usage slot for a key from the keystore.
    Returns the first successful key record alongside its remaining uses or (None, None) if unsuccessful."""
    matching_records = keystore.get_matching_key_records(name=key_name, active=True)

    if not matching_records:
        logger.debug(f"No active matching records found for key {key_name}")
        return (None, None)

    for key_record in matching_records:
        if not key_record.get("usable", False):
            logger.debug(f"Skipping unusable key {key_name} id {key_record['id']}")
            continue

        throttler.api_key_id = key_record["id"]
        remaining, slot_claimed = throttler.remaining_uses(claim_slot=True)

        if slot_claimed:
            logger.debug(f"Claimed slot for key {key_name} id {key_record['id']} ({remaining} uses left)")
            return (key_record, remaining)
        else:
            logger.debug(f"Key {key_name} id {key_record['id']} has {remaining} uses left - trying next")

    return (None, None)