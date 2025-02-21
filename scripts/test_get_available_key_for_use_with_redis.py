import os
from datetime import timedelta
from simple_keystore import SimpleKeyStore, SKSRateThrottler, get_available_key_for_use


REDIS_HOST = "localhost"  # Adjust if your container uses a different host (e.g., "redis")
REDIS_PORT = 6379  # Default Redis port


def test_get_available_key_for_use():
    """Test function to verify the behavior of get_available_key_for_use with Redis."""
    # Setup
    tmp_db = "tmp_get_available_key_for_use.db"
    key_name = "testkey"

    # Clean up existing temporary database
    if os.path.isfile(tmp_db):
        os.remove(tmp_db)

    # Initialize keystore and add test keys
    ks = SimpleKeyStore(tmp_db)
    ks.add_key(key_name, "key1", active=True)
    ks.add_key(key_name, "key2", active=True)
    ks.add_key(key_name, "key3", active=True)

    # Test scenario 1: All keys available, should return first key ("key1")
    result = get_available_key_for_use(
        key_name=key_name,
        keystore=ks,
        key_number_of_uses_allowed=3,
        key_use_window_in_seconds=10,
        redis_host=REDIS_HOST,
        redis_port=REDIS_PORT,
        how_long_to_try_in_seconds=5,
        verbose=True,
    )
    assert result == "key1", f"Expected 'key1' as first available key, but got {result}"
    print("Test 1 passed: Got first available key when all keys are fresh.")

    # Test scenario 2: Exhaust "key1", should return "key2"
    key_records = ks.get_matching_key_records(name=key_name)
    throttler = SKSRateThrottler(
        api_key_id=key_records[0]["id"],  # ID of "key1"
        number_of_uses_allowed=3,
        amount_of_time=timedelta(seconds=10),
        redis_host=REDIS_HOST,
        redis_port=REDIS_PORT,
    )
    # Exhaust key1's slots
    for _ in range(3):
        remaining, claimed = throttler.remaining_uses(claim_slot=True)
        assert claimed, f"Failed to claim slot for key1, remaining: {remaining}"

    # Now try to get an available key
    result = get_available_key_for_use(
        key_name=key_name,
        keystore=ks,
        key_number_of_uses_allowed=3,
        key_use_window_in_seconds=10,
        redis_host=REDIS_HOST,
        redis_port=REDIS_PORT,
        how_long_to_try_in_seconds=5,
        verbose=True,
    )
    assert result == "key2", f"Expected 'key2' after exhausting 'key1', but got {result}"
    print("Test 2 passed: Got next available key after exhausting first key.")

    # Test scenario 3: All keys exhausted, should raise TimeoutError
    # Exhaust remaining keys
    for record in key_records[1:]:  # key2 and key3
        throttler.api_key_id = record["id"]
        for _ in range(3):
            remaining, claimed = throttler.remaining_uses(claim_slot=True)
            assert claimed, f"Failed to claim slot for key {record['id']}, remaining: {remaining}"

    try:
        get_available_key_for_use(
            key_name=key_name,
            keystore=ks,
            key_number_of_uses_allowed=3,
            key_use_window_in_seconds=10,
            redis_host=REDIS_HOST,
            redis_port=REDIS_PORT,
            how_long_to_try_in_seconds=2,  # Short timeout for test
            verbose=True,
        )
        assert False, "Expected TimeoutError when all keys are exhausted"
    except TimeoutError:
        print("Test 3 passed: Correctly raised TimeoutError when no keys are available.")

    # Cleanup
    os.remove(tmp_db)


if __name__ == "__main__":
    test_get_available_key_for_use()
    print("All tests completed successfully!")
