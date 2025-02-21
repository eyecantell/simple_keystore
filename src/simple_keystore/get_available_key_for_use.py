# Looks for the first key it can find in the keystore that is usable active and not expired) and available
from simple_keystore import SimpleKeyStore, SKSRateThrottler
from datetime import timedelta
import time


def get_available_key_for_use(
    key_name: str,
    keystore: SimpleKeyStore,
    key_number_of_uses_allowed: int,
    key_use_window_in_seconds: int,
    redis_host: str,
    redis_port: int,
    how_long_to_try_in_seconds: int = 3600,
    verbose: bool = False,
) -> dict:
    """Returns the first key found (with the given key_name) that is usable (active and not expired) and available"""

    throttler = SKSRateThrottler(
        api_key_id=9999,
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
                # Got a slot!
                if verbose:
                    print(f"Found available key for use and claimed a slot for: {key_record_to_use}")
                return key_record_to_use["key"]

            elapsed = time.time() - start_time
            if elapsed >= how_long_to_try_in_seconds:
                raise TimeoutError(f"No {key_name} keys available after {how_long_to_try_in_seconds}s")

            if verbose:
                print(f"No keys available. Will try again in {wait_time_in_seconds:.1f}s")

            time.sleep(min(wait_time_in_seconds, 180))  # Max three minutes before attempts
            wait_time_in_seconds *= 1.5
        except TimeoutError:
            raise
        except Exception as e:
            if verbose:
                print(f"Error while waiting: {str(e)}")
            raise


def _attempt_to_grab_a_slot_from_available_keys(
    key_name: str, keystore: SimpleKeyStore, throttler: SKSRateThrottler, verbose: bool = False
) -> dict:
    """From the given keystore, try to claim a use for each key until successful. Try each key one time maximum"""

    matching_records = keystore.get_matching_key_records(
        name=key_name,
        active=True,
    )

    for key_record in matching_records:
        if not key_record["usable"]:
            continue

        # Point the throttler to this key
        throttler.api_key_id = key_record["id"]

        # Try to claim a slot (grab a use) for this key
        remaining, slot_claimed = throttler.remaining_uses(claim_slot=True)

        if slot_claimed:
            # Got a slot!
            if verbose:
                print(
                    f"Key {key_name} id {key_record['id']} can be used! ({remaining} uses remaining) - claimed a slot."
                )
            return key_record
        else:
            if verbose:
                print(f"Key {key_name} id {key_record['id']} has {remaining} uses remaining - will try next key.")

    # Was not able to get a slot for a key
    return None
