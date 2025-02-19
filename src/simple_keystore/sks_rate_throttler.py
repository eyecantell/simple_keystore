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

    def set_rate_limit(self, number_of_uses_allowed: int, amount_of_time: timedelta):
        """Set our rate limit values."""
        if number_of_uses_allowed <= 0:
            raise ValueError("Number of uses allowed must be positive")
        if amount_of_time <= timedelta():
            raise ValueError("Amount of time must be positive")

        self.rate_limit_timedelta = amount_of_time
        self.rate_limit_uses_allowed = number_of_uses_allowed

    def is_rate_limited(self) -> tuple[bool, bool]:
        """
        Check if the API key is rate limited and atomically attempt to register a new request.
        Returns a tuple (is_limited, was_incremented):
        - is_limited: True if the client is rate limited (even after trying to increment).
        - was_incremented: True if a new request was successfully added, False otherwise.
        """
        current_time = int(time.time())
        window_start = current_time - self.rate_limit_timedelta.total_seconds()

        # Use a Redis pipeline with transactions for atomicity
        pipe = self.redis.pipeline()
        redis_key = f"ratelimit:{self.api_key_id}"

        # Start a transaction
        pipe.multi()

        # Queue commands to clean old entries and check current count
        pipe.zremrangebyscore(redis_key, 0, window_start)
        pipe.zcard(redis_key)

        # Queue the potential new timestamp (we'll decide later if it stays)
        pipe.zadd(redis_key, {str(current_time): current_time})

        # Queue the expiration
        pipe.expire(redis_key, self.rate_limit_timedelta.total_seconds())

        # Execute the transaction atomically
        results = pipe.execute()

        # Extract results
        num_removed = results[0]  # Result of zremrangebyscore
        current_count_before = results[1]  # Result of zcard (before potential add)
        zadd_result = results[2]  # Result of zadd (1 if added, 0 if not, but we’ll use logic)

        # Determine if we were rate limited
        is_limited = current_count_before >= self.rate_limit_uses_allowed

        # Determine if we successfully incremented
        # If we were already at or over the limit, the zadd shouldn't "count," but in this setup, it did add.
        # We need to correct this by removing the timestamp if we were limited.

        was_incremented = not is_limited  # Assume we incremented only if not limited

        if is_limited:
            # If we were limited, remove the timestamp we just added
            self.redis.zrem(redis_key, str(current_time))
            # Ensure expiration is still set
            self.redis.expire(redis_key, self.rate_limit_timedelta.total_seconds())
        else:
            # If not limited, the timestamp stays, and we're good
            pass

        return is_limited, was_incremented

    
    def wait_until_available(self, timeout: int = 3600):
        """Block until the API key is available for use or timeout occurs."""
        start_time = time.time()
        wait_time = 1  # Initial wait time in seconds

        while True:
            is_limited, was_incremented = self.is_rate_limited()
            if not is_limited and was_incremented:
                # We successfully claimed a slot, proceed
                return
            if time.time() - start_time >= timeout:
                raise TimeoutError(f"API key {self.api_key_id=} is still rate limited after the timeout period of {timeout}s")
            time.sleep(wait_time)
            wait_time = min(wait_time * 1.5, 60)  # Exponential backoff, cap at 60 seconds
