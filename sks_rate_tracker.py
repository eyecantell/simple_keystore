
from datetime import datetime, timedelta, timezone
# PRW todo add a way to track how often a key has been used in the past N hours, days, etc.
class SKSRateTracker:
    def __init__(self, key_id: int, number_of_uses_allowed: int, amount_of_time : timedelta):

        self.key_id = key_id
        ''' ID of the key in use'''

        self.rate_limit_timedelta : timedelta = None
        '''Time period over which the number of uses can be made'''

        self.rate_limit_uses_allowed : int = None
        '''Number of key uses allowed in the time period'''
    
        self.set_rate_limit(number_of_uses=number_of_uses_allowed, amount_of_time=amount_of_time)

    def set_rate_limit(self, number_of_uses_allowed: int, amount_of_time : timedelta):
        '''Set the rate limit values for this key'''
        self.rate_limit_timedelta = amount_of_time
        self.rate_limit_uses_allowed = number_of_uses_allowed

    def add_use(self):
        '''Add a usage instance of this key if there are uses remaining'''
        if not self.uses_remaining:
            raise RuntimeError("Out of uses for key")

        # This will add a record to the key_usage table in PostgreSQL

    def uses_remaining(self) -> int:
        '''Check to see how many key uses are still available'''
        # Query the db for any uses in the past self.rate_limit_timedelta period
        pass

    def cleanup_uses(self, age_as_timedelta : timedelta = timedelta(hours=24)):
        '''Remove uses that are older than age_as_timedelta'''
        pass