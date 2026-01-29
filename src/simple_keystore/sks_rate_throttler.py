from collections.abc import Callable
from datetime import timedelta

import redis
import time
import uuid


class SKSRateThrottler:
    _LUA_SCRIPT = """
    -- KEYS[1] - rate limit key
    -- ARGV[1] - current timestamp
    -- ARGV[2] - window start timestamp
    -- ARGV[3] - max requests allowed
    -- ARGV[4] - window size in seconds
    -- ARGV[5] - claim_slot (string "true" or "false")
    -- ARGV[6] - unique request id
    local key = KEYS[1]
    local current_time = tonumber(ARGV[1])
    local window_start = tonumber(ARGV[2])
    local max_requests = tonumber(ARGV[3])
    local window_size = tonumber(ARGV[4])
    local claim_slot = (ARGV[5] == "true")
    local request_id = ARGV[6]

    -- Remove expired entries
    redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

    -- Count current entries in window
    local current_count = redis.call('ZCARD', key)
    local remaining = max_requests - current_count

    if claim_slot and remaining > 0 then
        -- Use unique identifier as member to prevent overwriting
        redis.call('ZADD', key, current_time, request_id .. ':' .. current_time)
        redis.call('EXPIRE', key, window_size)
        return {remaining - 1, true}
    else
        return {remaining, false}
    end
    """

    def __init__(
        self,
        api_key_id: int,
        number_of_uses_allowed: int,
        amount_of_time: timedelta,
        redis_client: redis.Redis | None = None,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_db: int = 0,
    ):
        if redis_client is None:
            self._redis = redis.Redis(host=redis_host, port=redis_port, db=redis_db)
        else:
            self._redis = redis_client
        self._owns_redis = redis_client is None

        self._default_api_key_id = api_key_id
        self._set_rate_limit(number_of_uses_allowed, amount_of_time)

        try:
            self._lua_script_sha = self._redis.script_load(self._LUA_SCRIPT)
        except Exception as e:
            raise RuntimeError(f"Failed to load Lua script: {e}")

    @property
    def redis(self) -> redis.Redis:
        return self._redis

    @property
    def api_key_id(self) -> int:
        return self._default_api_key_id

    @api_key_id.setter
    def api_key_id(self, value: int) -> None:
        self._default_api_key_id = value

    def _set_rate_limit(self, number_of_uses_allowed: int, amount_of_time: timedelta):
        """Set rate limit values (internal use)."""
        if number_of_uses_allowed <= 0:
            raise ValueError("Number of uses allowed must be positive")
        if amount_of_time <= timedelta():
            raise ValueError("Amount of time must be positive")
        self.rate_limit_timedelta = amount_of_time
        self.rate_limit_uses_allowed = number_of_uses_allowed

    def remaining_uses(self, claim_slot: bool = False, api_key_id: int | None = None) -> tuple[int, bool]:
        """Check if the API key is rate limited and optionally claim a use.
        Args:
            claim_slot: If True, attempt to claim a usage slot.
            api_key_id: Override the default api_key_id for this call.
        Returns (remaining: int, slot_claimed: bool)."""
        effective_api_key_id = api_key_id if api_key_id is not None else self._default_api_key_id
        current_time = int(time.time())
        window_start = current_time - self.rate_limit_timedelta.total_seconds()
        window_duration = self.rate_limit_timedelta.total_seconds()

        # Generate a unique request ID
        request_id = str(uuid.uuid4())

        try:
            remaining, slot_claimed = self._redis.evalsha(
                self._lua_script_sha,
                1,
                f"ratelimit:{effective_api_key_id}",
                str(current_time),
                str(window_start),
                str(self.rate_limit_uses_allowed),
                str(window_duration),
                str(claim_slot).lower(),
                request_id,
            )
            return (int(remaining), bool(slot_claimed))
        except Exception as e:
            raise RuntimeError(f"Failed to check rate limit for API key {effective_api_key_id}: {str(e)}") from e

    def wait_until_available(
        self,
        timeout: int = 7200,
        verbose: bool = False,
        api_key_id: int | None = None,
        sleep_func: Callable[[float], None] | None = None,
        clock_func: Callable[[], float] | None = None,
    ) -> int:
        """Block until an API key slot is claimed or timeout occurs.
        Args:
            timeout (int): Max wait time in seconds (default: 7200, i.e., 2 hours).
            verbose (bool): If True, print status updates.
            api_key_id: Override the default api_key_id for this call.
            sleep_func: Optional callable to use instead of time.sleep.
            clock_func: Optional callable to use instead of time.time.
        Returns:
            int: Number of remaining uses after claiming a slot.
        Raises:
            TimeoutError: If no slot is available within timeout.
        """
        effective_api_key_id = api_key_id if api_key_id is not None else self._default_api_key_id
        _sleep = sleep_func if sleep_func is not None else time.sleep
        _clock = clock_func if clock_func is not None else time.time

        start_time = _clock()
        wait_time_in_seconds = 1.0
        while True:
            try:
                remaining, slot_claimed = self.remaining_uses(claim_slot=True, api_key_id=effective_api_key_id)
                if slot_claimed:
                    if verbose:
                        print(f"Claimed a slot! Remaining uses: {remaining}")
                    return remaining
                elapsed = _clock() - start_time
                if elapsed >= timeout:
                    raise TimeoutError(f"API key {effective_api_key_id} still unavailable after {timeout}s")
                if verbose:
                    print(
                        f"Waiting for key {effective_api_key_id} - "
                        f"remaining uses: {remaining} - "
                        f"sleeping {wait_time_in_seconds:.1f}s"
                    )
                max_wait = min(self.rate_limit_timedelta.total_seconds(), 180)
                _sleep(min(wait_time_in_seconds, max_wait))
                wait_time_in_seconds *= 1.5
            except TimeoutError:
                raise
            except Exception as e:
                if verbose:
                    print(f"Error while waiting: {str(e)}")
                raise

    def __del__(self):
        """Clean up Redis connection on object destruction."""
        if self._owns_redis:
            self._redis.close()
