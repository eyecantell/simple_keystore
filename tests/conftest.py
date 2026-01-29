import pytest
from datetime import timedelta
from fakeredis import FakeStrictRedis
from simple_keystore import SKSRateThrottler


# Fixture for fake Redis instance with mocked Lua scripting
@pytest.fixture
def fake_redis(monkeypatch):
    redis_instance = FakeStrictRedis()

    def mock_script_load(script):
        return "mocked_sha1"

    monkeypatch.setattr(redis_instance, "script_load", mock_script_load)

    def mock_evalsha(sha, numkeys, *args):
        if sha != "mocked_sha1":
            raise ValueError("Invalid script SHA")

        # Extract arguments (handle the case where request_id might be present)
        key = args[0]
        current_time = int(args[1])
        window_start = float(args[2])
        max_requests = int(args[3])
        window_size = float(args[4])
        claim_slot = args[5].lower() == "true"

        # Check for additional request_id parameter (safely)
        request_id = args[6] if len(args) > 6 else str(current_time)

        # Implement the Lua script logic
        redis_instance.zremrangebyscore(key, "-inf", window_start)
        current_count = redis_instance.zcard(key)
        remaining = max_requests - current_count

        print(f"Evalsha: key={key}, current_count={current_count}, remaining={remaining}, claim_slot={claim_slot}")

        if claim_slot and remaining > 0:
            # Use unique member identifier as in the fixed implementation
            member_key = f"{request_id}:{current_time}"
            redis_instance.zadd(key, {member_key: current_time})
            redis_instance.expire(key, int(window_size))
            print(f"Slot claimed, member: {member_key}")
            return [remaining - 1, 1]

        print("Slot not claimed")
        return [remaining, 0]

    monkeypatch.setattr(redis_instance, "evalsha", mock_evalsha)
    return redis_instance


# Fixture for throttler using fake Redis
@pytest.fixture
def throttler(fake_redis):
    return SKSRateThrottler(
        api_key_id=1, number_of_uses_allowed=5, amount_of_time=timedelta(seconds=60), redis_client=fake_redis
    )
