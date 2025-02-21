from datetime import timedelta
from typing import Optional, Tuple
import redis
import time
import uuid


class SKSRateThrottler:
    def __init__(
        self,
        api_key_id: int,
        number_of_uses_allowed: int,
        amount_of_time: timedelta,
        redis_client: Optional[redis.Redis] = None,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_db: int = 0,
    ):
        if redis_client is None:
            self.redis = redis.Redis(host=redis_host, port=redis_port, db=redis_db)
        else:
            self.redis = redis_client

        self.api_key_id = api_key_id
        self._set_rate_limit(number_of_uses_allowed, amount_of_time)

        # Load the Lua script with unique member handling
        lua_increment_script = """
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
        try:
            self.lua_increment_script_sha = self.redis.script_load(lua_increment_script)
        except Exception as e:
            raise RuntimeError(f"Failed to load Lua script: {e}")

    def _set_rate_limit(self, number_of_uses_allowed: int, amount_of_time: timedelta):
        """Set rate limit values (internal use)."""
        if number_of_uses_allowed <= 0:
            raise ValueError("Number of uses allowed must be positive")
        if amount_of_time <= timedelta():
            raise ValueError("Amount of time must be positive")
        self.rate_limit_timedelta = amount_of_time
        self.rate_limit_uses_allowed = number_of_uses_allowed

    def remaining_uses(self, claim_slot: bool = False) -> Tuple[int, bool]:
        """Check if the API key is rate limited and optionally claim a use.
        Returns (remaining: int, slot_claimed: bool)."""
        current_time = int(time.time())
        window_start = current_time - self.rate_limit_timedelta.total_seconds()
        window_duration = self.rate_limit_timedelta.total_seconds()

        # Generate a unique request ID
        request_id = str(uuid.uuid4())

        try:
            remaining, slot_claimed = self.redis.evalsha(
                self.lua_increment_script_sha,
                1,
                f"ratelimit:{self.api_key_id}",
                str(current_time),
                str(window_start),
                str(self.rate_limit_uses_allowed),
                str(window_duration),
                str(claim_slot).lower(),
                request_id,
            )
            return (int(remaining), bool(slot_claimed))
        except Exception as e:
            raise Exception(f"Failed to check rate limit for API key {self.api_key_id}: {str(e)}")

    def wait_until_available(self, timeout: int = 7200, verbose: bool = False) -> int:
        """Block until an API key slot is claimed or timeout occurs.
        Args:
            timeout (int): Max wait time in seconds (default: 7200, i.e., 2 hours).
            verbose (bool): If True, print status updates.
        Returns:
            int: Number of remaining uses after claiming a slot.
        Raises:
            TimeoutError: If no slot is available within timeout.
        """
        start_time = time.time()
        wait_time_in_seconds = 1.0
        while True:
            try:
                remaining, slot_claimed = self.remaining_uses(claim_slot=True)
                if slot_claimed:
                    if verbose:
                        print(f"Claimed a slot! Remaining uses: {remaining}")
                    return remaining
                elapsed = time.time() - start_time
                if elapsed >= timeout:
                    raise TimeoutError(f"API key {self.api_key_id} still unavailable after {timeout}s")
                if verbose:
                    print(
                        f"Waiting for key {self.api_key_id} - "
                        f"remaining uses: {remaining} - "
                        f"sleeping {wait_time_in_seconds:.1f}s"
                    )
                max_wait = min(self.rate_limit_timedelta.total_seconds(), 180)
                time.sleep(min(wait_time_in_seconds, max_wait))
                wait_time_in_seconds *= 1.5
            except TimeoutError:
                raise
            except Exception as e:
                if verbose:
                    print(f"Error while waiting: {str(e)}")
                raise

    def __del__(self):
        """Clean up Redis connection on object destruction."""
        self.redis.close()
