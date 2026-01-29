import pytest
from datetime import timedelta
import time
from freezegun import freeze_time
from simple_keystore import SKSRateThrottler


def test_invalid_initialization():
    """Test that initialization with invalid parameters raises ValueError."""
    with pytest.raises(ValueError):
        SKSRateThrottler(api_key_id=1, number_of_uses_allowed=-1, amount_of_time=timedelta(seconds=60))

    with pytest.raises(ValueError):
        SKSRateThrottler(api_key_id=1, number_of_uses_allowed=0, amount_of_time=timedelta(seconds=60))

    with pytest.raises(ValueError):
        SKSRateThrottler(api_key_id=1, number_of_uses_allowed=5, amount_of_time=timedelta(seconds=-1))

    with pytest.raises(ValueError):
        SKSRateThrottler(api_key_id=1, number_of_uses_allowed=5, amount_of_time=timedelta(seconds=0))


@freeze_time("2023-01-01 00:00:00")
def test_remaining_uses_no_previous_uses(throttler):
    """Test remaining_uses with no prior usage."""
    remaining, slot_claimed = throttler.remaining_uses(claim_slot=False)
    assert remaining == 5
    assert not slot_claimed

    remaining, slot_claimed = throttler.remaining_uses(claim_slot=True)
    assert remaining == 4
    assert slot_claimed

    remaining, slot_claimed = throttler.remaining_uses(claim_slot=False)
    assert remaining == 4
    assert not slot_claimed


@freeze_time("2023-01-01 00:00:00")
def test_remaining_uses_with_previous_and_expired_uses(fake_redis):
    throttler = SKSRateThrottler(
        api_key_id=1, number_of_uses_allowed=3, amount_of_time=timedelta(seconds=60), redis_client=fake_redis
    )
    current_time = int(time.time())
    key = "ratelimit:1"

    # Add items to the sorted set using the same format as in our fixed implementation
    expired_time = current_time - 70
    recent_time = current_time - 10
    fake_redis.zadd(
        key,
        {
            f"test-expired:{expired_time}": expired_time,  # Expired
            f"test-recent:{recent_time}": recent_time,  # Within window
        },
    )

    print(f"Initial state: {fake_redis.zrange(key, 0, -1, withscores=True)}")

    remaining, slot_claimed = throttler.remaining_uses(claim_slot=False)
    print(f"After no claim: remaining={remaining}, slot_claimed={slot_claimed}")
    assert remaining == 2  # 3 allowed - 1 within window = 2 remaining
    assert not slot_claimed

    remaining, slot_claimed = throttler.remaining_uses(claim_slot=True)
    print(f"After first claim: remaining={remaining}, slot_claimed={slot_claimed}")
    assert remaining == 1  # 2 remaining - 1 claimed = 1 remaining
    assert slot_claimed

    remaining, slot_claimed = throttler.remaining_uses(claim_slot=True)
    print(f"After second claim: remaining={remaining}, slot_claimed={slot_claimed}")
    assert remaining == 0  # 1 remaining - 1 claimed = 0 remaining
    assert slot_claimed

    remaining, slot_claimed = throttler.remaining_uses(claim_slot=True)
    print(f"After third claim: remaining={remaining}, slot_claimed={slot_claimed}")
    assert remaining == 0  # Still 0 remaining, can't claim
    assert not slot_claimed


@freeze_time("2023-01-01 00:00:00")
def test_wait_until_available_immediate(throttler):
    """Test wait_until_available when a slot is available immediately."""
    start_time = time.time()
    remaining = throttler.wait_until_available(timeout=5, verbose=False)
    elapsed = time.time() - start_time
    assert remaining == 4  # 5 - 1 = 4 after claiming
    assert elapsed < 1  # Should return almost instantly


def test_del_does_not_close_injected_client(fake_redis):
    """Step 1: __del__ should not close an injected (borrowed) Redis client."""
    throttler = SKSRateThrottler(
        api_key_id=1, number_of_uses_allowed=5, amount_of_time=timedelta(seconds=60), redis_client=fake_redis
    )
    throttler.__del__()
    # The borrowed client should still be usable after __del__
    fake_redis.ping()


@freeze_time("2023-01-01 00:00:00")
def test_remaining_uses_with_explicit_api_key_id(throttler):
    """Step 4: per-call api_key_id should use a separate rate bucket."""
    # Claim all 5 slots for the default api_key_id (1)
    for _ in range(5):
        throttler.remaining_uses(claim_slot=True)

    # Default key should now be exhausted
    remaining, claimed = throttler.remaining_uses(claim_slot=True)
    assert remaining == 0
    assert not claimed

    # A different api_key_id should have its own independent bucket
    remaining, claimed = throttler.remaining_uses(claim_slot=True, api_key_id=999)
    assert remaining == 4
    assert claimed


@freeze_time("2023-01-01 00:00:00")
def test_wait_until_available_timeout(fake_redis):
    """Step 5: verify TimeoutError raised without real sleeping using injected clock/sleep."""
    throttler = SKSRateThrottler(
        api_key_id=1, number_of_uses_allowed=1, amount_of_time=timedelta(seconds=60), redis_client=fake_redis
    )
    # Exhaust the single slot
    throttler.remaining_uses(claim_slot=True)

    fake_time = [0.0]

    def fake_clock():
        return fake_time[0]

    def fake_sleep(seconds):
        fake_time[0] += seconds

    with pytest.raises(TimeoutError, match="still unavailable after 10s"):
        throttler.wait_until_available(timeout=10, clock_func=fake_clock, sleep_func=fake_sleep)


@freeze_time("2023-01-01 00:00:00")
def test_wait_until_available_backoff(fake_redis):
    """Step 5: verify sleep durations follow 1.0, 1.5, 2.25... capped at min(window, 180)."""
    throttler = SKSRateThrottler(
        api_key_id=1, number_of_uses_allowed=1, amount_of_time=timedelta(seconds=60), redis_client=fake_redis
    )
    # Exhaust the single slot
    throttler.remaining_uses(claim_slot=True)

    sleep_durations = []
    fake_time = [0.0]

    def fake_clock():
        return fake_time[0]

    def fake_sleep(seconds):
        sleep_durations.append(seconds)
        fake_time[0] += seconds

    with pytest.raises(TimeoutError):
        throttler.wait_until_available(timeout=20, clock_func=fake_clock, sleep_func=fake_sleep)

    # Expected: 1.0, 1.5, 2.25, 3.375, 5.0625, ... all capped at min(60, 180) = 60
    assert len(sleep_durations) >= 3
    assert sleep_durations[0] == pytest.approx(1.0)
    assert sleep_durations[1] == pytest.approx(1.5)
    assert sleep_durations[2] == pytest.approx(2.25)


@freeze_time("2023-01-01 00:00:00")
def test_wait_until_available_verbose(throttler, capsys):
    """Step 5: verify print output when verbose=True."""
    remaining = throttler.wait_until_available(timeout=5, verbose=True)
    captured = capsys.readouterr()
    assert "Claimed a slot!" in captured.out
    assert remaining == 4
