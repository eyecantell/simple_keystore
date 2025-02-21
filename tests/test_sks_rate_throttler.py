import pytest
from datetime import timedelta
import time
from fakeredis import FakeStrictRedis
from freezegun import freeze_time
from unittest.mock import Mock
from simple_keystore import SKSRateThrottler

# Fixture for fake Redis instance with mocked Lua scripting
@pytest.fixture
def fake_redis(monkeypatch):
    redis_instance = FakeStrictRedis()
    def mock_script_load(script):
        return "mocked_sha1"
    monkeypatch.setattr(redis_instance, 'script_load', mock_script_load)
    def mock_evalsha(sha, numkeys, *args):
        if sha != "mocked_sha1":
            raise ValueError("Invalid script SHA")
        key, current_time, window_start, max_requests, window_size, claim_slot = args
        current_time = int(current_time)
        window_start = float(window_start)
        max_requests = int(max_requests)
        window_size = float(window_size)
        claim_slot = claim_slot.lower() == "true"
        redis_instance.zremrangebyscore(key, '-inf', window_start)
        current_count = redis_instance.zcard(key)
        remaining = max_requests - current_count
        print(f"Evalsha: key={key}, current_count={current_count}, remaining={remaining}, claim_slot={claim_slot}")
        if claim_slot and remaining > 0:
            redis_instance.zadd(key, {str(current_time): current_time})
            redis_instance.expire(key, int(window_size))
            print("Slot claimed")
            return [remaining - 1, 1]
        print("Slot not claimed")
        return [remaining, 0]
    monkeypatch.setattr(redis_instance, 'evalsha', mock_evalsha)
    return redis_instance

# Fixture for throttler using fake Redis
@pytest.fixture
def throttler(fake_redis):
    return SKSRateThrottler(
        api_key_id=1,
        number_of_uses_allowed=5,
        amount_of_time=timedelta(seconds=60),
        redis_client=fake_redis
    )

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

@freeze_time('2023-01-01 00:00:00')
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

@freeze_time('2023-01-01 00:00:00')
def test_remaining_uses_with_previous_and_expired_uses(fake_redis):
    throttler = SKSRateThrottler(
        api_key_id=1,
        number_of_uses_allowed=3,
        amount_of_time=timedelta(seconds=60),
        redis_client=fake_redis
    )
    current_time = int(time.time())
    key = "ratelimit:1"
    fake_redis.zadd(key, {
        str(current_time - 70): current_time - 70,  # Expired
        str(current_time - 10): current_time - 10   # Within window
    })
    print(f"Initial state: {fake_redis.zrange(key, 0, -1, withscores=True)}")

    remaining, slot_claimed = throttler.remaining_uses(claim_slot=False)
    print(f"After no claim: remaining={remaining}, slot_claimed={slot_claimed}")
    assert remaining == 2
    assert not slot_claimed

    remaining, slot_claimed = throttler.remaining_uses(claim_slot=True)
    print(f"After first claim: remaining={remaining}, slot_claimed={slot_claimed}")
    assert remaining == 1
    assert slot_claimed

    remaining, slot_claimed = throttler.remaining_uses(claim_slot=True)
    print(f"After second claim: remaining={remaining}, slot_claimed={slot_claimed}")
    assert remaining == 0
    assert slot_claimed

    remaining, slot_claimed = throttler.remaining_uses(claim_slot=True)
    print(f"After third claim: remaining={remaining}, slot_claimed={slot_claimed}")
    assert remaining == 0
    assert not slot_claimed

@freeze_time('2023-01-01 00:00:00')
def test_wait_until_available_immediate(throttler):
    """Test wait_until_available when a slot is available immediately."""
    start_time = time.time()
    remaining = throttler.wait_until_available(timeout=5, verbose=False)
    elapsed = time.time() - start_time
    assert remaining == 4  # 5 - 1 = 4 after claiming
    assert elapsed < 1  # Should return almost instantly

@freeze_time('2023-01-01 00:00:00', auto_tick_seconds=1)
def test_wait_until_available_after_delay(fake_redis):
    throttler = SKSRateThrottler(
        api_key_id=1,
        number_of_uses_allowed=1,
        amount_of_time=timedelta(seconds=2),
        redis_client=fake_redis
    )
    # Claim the slot
    throttler.remaining_uses(claim_slot=True)
    # Wait should succeed after ~2 seconds
    start = time.time()
    throttler.wait_until_available(timeout=5)
    duration = time.time() - start
    assert 1.5 <= duration <= 2.5  # Approximate window duration

@freeze_time('2023-01-01 00:00:00')
def test_wait_until_available_timeout(fake_redis):
    """Test wait_until_available raises TimeoutError when no slots become available."""
    throttler = SKSRateThrottler(
        api_key_id=1,
        number_of_uses_allowed=1,
        amount_of_time=timedelta(seconds=10),
        redis_client=fake_redis
    )
    throttler.remaining_uses(claim_slot=True)

    with pytest.raises(TimeoutError):
        throttler.wait_until_available(timeout=2, verbose=False)

@freeze_time('2023-01-01 00:00:00')
def test_wait_until_available_verbose(fake_redis, capsys):
    """Test wait_until_available verbose output."""
    throttler = SKSRateThrottler(
        api_key_id=1,
        number_of_uses_allowed=1,
        amount_of_time=timedelta(seconds=10),
        redis_client=fake_redis
    )
    throttler.remaining_uses(claim_slot=True)

    with pytest.raises(TimeoutError):
        throttler.wait_until_available(timeout=2, verbose=True)
    captured = capsys.readouterr()
    assert "Waiting for key 1" in captured.out
    assert "sleeping" in captured.out

def test_cleanup_on_del(fake_redis, monkeypatch):
    """Test that Redis connection is closed on object deletion."""
    throttler = SKSRateThrottler(
        api_key_id=1,
        number_of_uses_allowed=5,
        amount_of_time=timedelta(seconds=60),
        redis_client=fake_redis
    )
    close_called = [False]
    def mock_close():
        close_called[0] = True
    monkeypatch.setattr(fake_redis, 'close', mock_close)
    del throttler
    assert close_called[0]

if __name__ == '__main__':
    pytest.main(['-v'])