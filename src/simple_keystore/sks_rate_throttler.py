from uuid import uuid4
import psycopg
from datetime import datetime, timedelta, timezone
from typing import Optional
from simple_keystore import SKSRateTracker

class SKSRateThrottler:
    def __init__(self, api_key_id: int, number_of_uses_allowed: int, amount_of_time: timedelta, 
                 db_config: Optional[dict] = None, create_db_if_dne: bool = False):
        """Initialize the rate throttler with a key ID and rate limit settings.
        """
        self.tracker = SKSRateTracker(api_key_id=api_key_id, number_of_uses_allowed=number_of_uses_allowed, amount_of_time=amount_of_time, db_config=db_config, create_db_if_dne=create_db_if_dne)
        self.uuid = uuid4() # Keep each throttle requestor unique

    def add_use_request():
        pass

    def block_until_next_use_available():
        pass
        