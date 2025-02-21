from datetime import timedelta
import os
import logging
from simple_keystore import SimpleKeyStore, SKSRateThrottler, get_available_key_for_use

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Default level
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)
REDIS_HOST = "localhost"
REDIS_PORT = 6379

def test_get_available_key_for_use():
    """Test function to verify the behavior of get_available_key_for_use with Redis."""
    # Setup
    tmp_db = "tmp_get_available_key_for_use.db"
    key_name = "testkey"

    if os.path.isfile(tmp_db):
        logger.debug(f"Removed {tmp_db} in order to start fresh")
        os.remove(tmp_db)

    ks = SimpleKeyStore(tmp_db)
    # Add our test keys
    ks.add_key(key_name, "key1", active=True)
    ks.add_key(key_name, "key2", active=True)
    ks.add_key(key_name, "key3", active=True)

    # Test scenario 1: All keys available
    logger.info("Starting Test 1: All keys available")
    result = get_available_key_for_use(
        key_name=key_name,
        keystore=ks,
        key_number_of_uses_allowed=3,
        key_use_window_in_seconds=10,
        redis_host=REDIS_HOST,
        redis_port=REDIS_PORT,
        how_long_to_try_in_seconds=5,
    )
    assert result == "key1", f"Expected 'key1' as first available key, but got {result}"
    logger.info("Test 1 passed: Got first available key when all keys are fresh.")

    # Test scenario 2: Exhaust "key1"
    logger.info("Starting Test 2: Exhaust first key")
    key_records = ks.get_matching_key_records(name=key_name)
    throttler = SKSRateThrottler(
        api_key_id=key_records[0]["id"],  # ID of "key1"
        number_of_uses_allowed=3,
        amount_of_time=timedelta(seconds=10),
        redis_host=REDIS_HOST,
        redis_port=REDIS_PORT,
    )

    # One slot for key1 was claimed above via get_available_key_for_use, exhaust the two remaining
    for i in range(2):
        remaining, claimed = throttler.remaining_uses(claim_slot=True)
        assert claimed, f"Failed to claim slot {i+2} for key1, remaining: {remaining}"
        logger.debug(f"Claimed slot {i+2} for key1, remaining: {remaining}")

    result = get_available_key_for_use(
        key_name=key_name,
        keystore=ks,
        key_number_of_uses_allowed=3,
        key_use_window_in_seconds=10,
        redis_host=REDIS_HOST,
        redis_port=REDIS_PORT,
        how_long_to_try_in_seconds=5,
    )
    assert result == "key2", f"Expected 'key2' after exhausting 'key1', but got {result}"
    logger.info("Test 2 passed: Got next available key after exhausting first key.")

    # Test scenario 3: All keys exhausted
    logger.info("Starting Test 3: Exhaust all keys")

    # Exhaust the remaining key2 uses
    throttler.api_key_id = 2
    for i in range(2):
        remaining, claimed = throttler.remaining_uses(claim_slot=True)
        assert claimed, f"Failed to claim slot for key {throttler.api_key_id}, remaining: {remaining}"
        logger.debug(f"Claimed slot for key {throttler.api_key_id}, remaining: {remaining}")

    # Exhaust the key3 uses
    throttler.api_key_id = 3
    for i in range(3):
        remaining, claimed = throttler.remaining_uses(claim_slot=True)
        assert claimed, f"Failed to claim slot for key {throttler.api_key_id}, remaining: {remaining}"
        logger.debug(f"Claimed slot for key {throttler.api_key_id}, remaining: {remaining}")
    

    try:
        get_available_key_for_use(
            key_name=key_name,
            keystore=ks,
            key_number_of_uses_allowed=3,
            key_use_window_in_seconds=10,
            redis_host=REDIS_HOST,
            redis_port=REDIS_PORT,
            how_long_to_try_in_seconds=2,
        )
        assert False, "Expected TimeoutError when all keys are exhausted"
    except TimeoutError:
        logger.info("Test 3 passed: Correctly raised TimeoutError when no keys are available.")

    os.remove(tmp_db)

if __name__ == "__main__":
    # Uncomment to enable DEBUG logging
    # logging.getLogger().setLevel(logging.DEBUG)
    test_get_available_key_for_use()
    logger.info("All tests completed successfully!")