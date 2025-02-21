from datetime import timedelta
from simple_keystore import SKSRateThrottler

def test_rate_throttler():
    # Initialize the throttler with an API key ID, 5 uses allowed in 10 seconds
    throttler = SKSRateThrottler(
        api_key_id=1,
        number_of_uses_allowed=5,
        amount_of_time=timedelta(seconds=5)
    )

    print("Starting test...")

    # Test 1: Check remaining uses without claiming
    remaining, claimed = throttler.remaining_uses(claim_slot=False)
    print(f"Initial remaining uses (no claim): {remaining}, Slot claimed: {claimed}")
    assert remaining == throttler.rate_limit_uses_allowed

    # Test 2: Claim slots and observe rate limiting
    expected_remaining = throttler.rate_limit_uses_allowed
    for i in range(throttler.rate_limit_uses_allowed + 3):  # Try more times than allowed to see throttling
        remaining, claimed = throttler.remaining_uses(claim_slot=True)
        print(f"Attempt {i+1}: Remaining uses: {remaining}, Slot claimed: {claimed}")
        expected_remaining -= 1
        assert remaining == max(0, expected_remaining), f"Expected {max(0, expected_remaining)} after {throttler.rate_limit_uses_allowed - expected_remaining} uses, but got {remaining}"
        if expected_remaining >= 0:
            assert claimed == True, f"Expected claimed to be True when expected_remaining is {expected_remaining}"
        else:
            assert claimed == False, f"Expected claimed to be False when expected_remaining is zero"

        

    # Test 3: Wait until a slot is available
    print("\nWaiting for a slot to become available...")
    remaining = throttler.wait_until_available(timeout=7, verbose=True)
    print(f"After waiting, remaining uses: {remaining}")

    # Test 4: Check Redis state directly (optional)
    print("\nChecking Redis state:")
    redis_client = throttler.redis
    key = "ratelimit:1"
    timestamps = redis_client.zrange(key, 0, -1, withscores=True)
    print(f"Timestamps in Redis for key {key}: {timestamps}")

if __name__ == "__main__":
    test_rate_throttler()