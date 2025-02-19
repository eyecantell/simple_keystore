from datetime import datetime, timedelta
import time
import redis


class SKSRateThrottler:
    '''User Redis to throttle the number of api requests in a rolling window'''

    def __init__(
        self,
        api_key_id: int,
        number_of_uses_allowed: int,
        amount_of_time: timedelta,
        redis_host: str = "localhost", 
        redis_port: int = 6379,
        redis_db : int = 0
    ):
        
        self.redis = redis.Redis(host=redis_host, port=redis_port, db=redis_db)

        self.api_key_id = api_key_id
        self.rate_limit_timedelta : timedelta = None
        self.rate_limit_uses_allowed: int = None
        # Set the rate limit with the passed values
        self.set_rate_limit(number_of_uses_allowed, amount_of_time)
    

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
        Check if our api key is rate limited using a sliding window approach.
        Returns True if rate limited, False otherwise.

        It might seem counterintuitive to add a new request timestamp while checking the limit, but this provides atomicity.

        By doing everything in one pipeline, you ensure that no other process can interfere between checking the count and adding the new request. 
        This prevents race conditions where two clients might both think the limit hasn’t been reached and both try to make a request.
        """
        current_time = int(time.time())
        window_start = current_time - self.rate_limit_timedelta.total_seconds() 
        
        # Use a Redis pipeline for atomic operations
        pipe = self.redis.pipeline()
        
        # Key for this API key's requests
        redis_key = f"ratelimit:{self.api_key_id}"
        
        # Remove requests older than the window
        pipe.zremrangebyscore(redis_key, 0, window_start)
        
        # Count requests within current window
        pipe.zcard(redis_key)
        
        # Add current request with current timestamp
        pipe.zadd(redis_key, {str(current_time): current_time})
        
        # Set expiration to ensure cleanup
        pipe.expire(redis_key, self.rate_limit_timedelta.total_seconds())
        
        # Execute all commands
        _, current_count, _, _ = pipe.execute()
        
        # Check if rate limited
        return current_count > self.rate_limit_uses_allowed

    def wait_until_available(self, timeout: int = 3600):
        """Block until the API key is available for use or timeout occurs."""
        start_time = time.time()
        while self.is_rate_limited():
            if time.time() - start_time >= timeout:
                raise TimeoutError(f"API key {self.api_key_id=} is still rate limited after the timeout period of {timeout}s")
            time.sleep(1)  # Adjust the sleep time as needed
