from datetime import datetime, timedelta
import time
import redis

class SKSRateThrottler:
    '''Use Redis to throttle the number of API requests in a rolling window'''

    def __init__(
        self,
        api_key_id: int,
        number_of_uses_allowed: int,
        amount_of_time: timedelta,
        redis_host: str = "localhost", 
        redis_port: int = 6379,
        redis_db: int = 0
    ):
        self.redis = redis.Redis(host=redis_host, port=redis_port, db=redis_db)
        self.api_key_id = api_key_id
        self.rate_limit_timedelta = None
        self.rate_limit_uses_allowed = None
        self.set_rate_limit(number_of_uses_allowed, amount_of_time)

        # Load the Lua script
        lua_increment_script = """
        local redis_key = KEYS[1]
        local current_time = ARGV[1]
        local window_start = ARGV[2]
        local max_uses = tonumber(ARGV[3])
        local window_duration_in_sec = tonumber(ARGV[4])

        redis.call("ZREMRANGEBYSCORE", redis_key, 0, window_start)
        local current_count = redis.call("ZCARD", redis_key)

        local can_increment = current_count < max_uses

        if can_increment then
            redis.call("ZADD", redis_key, current_time, current_time)
        else
            local exists = redis.call("EXISTS", redis_key)
            if exists == 1 then
                redis.call("EXPIRE", redis_key, math.ceil(window_duration_in_sec))
            end
            return 0
        end

        redis.call("EXPIRE", redis_key, math.ceil(window_duration_in_sec))

        return 1
        """
 
        try:
            self.lua_increment_script_sha = self.redis.script_load(lua_increment_script) # Get the script SHA for faster execution
        except Exception as e:
            raise RuntimeError(f"Failed to load Lua script: {e}")

    def set_rate_limit(self, number_of_uses_allowed: int, amount_of_time: timedelta):
        """Set our rate limit values."""
        if number_of_uses_allowed <= 0:
            raise ValueError("Number of uses allowed must be positive")
        if amount_of_time <= timedelta():
            raise ValueError("Amount of time must be positive")

        self.rate_limit_timedelta = amount_of_time
        self.rate_limit_uses_allowed = number_of_uses_allowed

    def is_rate_limited(self) -> bool:
        """
        Check if the API key is rate limited and atomically attempt to register a new request.
        Returns True if the client is rate limited (no increment occurred), False otherwise (increment occurred).
        """
        current_time = int(time.time())
        window_start = current_time - self.rate_limit_timedelta.total_seconds()
        window_duration = self.rate_limit_timedelta.total_seconds()

        # Execute the Lua script
        was_incremented = self.redis.evalsha(
            self.lua_increment_script_sha,
            1,  # Number of keys
            f"ratelimit:{self.api_key_id}",  # Key 1
            str(current_time),  # Arg 1: current timestamp
            str(window_start),  # Arg 2: window start time
            str(self.rate_limit_uses_allowed),  # Arg 3: max uses allowed
            str(window_duration)  # Arg 4: window duration in seconds
        )

        # Lua returns 1 for success (incremented) and 0 for failure (rate-limited)
        return not bool(was_incremented)  # Return True if rate-limited, False if not

    def wait_until_available(self, timeout: int = 3600):
        """Block until the API key is available for use or timeout occurs."""
        start_time = time.time()
        wait_time_in_seconds = 1
        while self.is_rate_limited():
            if time.time() - start_time >= timeout:
                raise TimeoutError(f"API key {self.api_key_id=} is still rate limited after the timeout period of {timeout}s")
            time.sleep(min(wait_time_in_seconds, 120)) # cap wait time to 120 seconds
            wait_time_in_seconds *= 1.5