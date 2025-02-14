from datetime import datetime, timedelta, timezone
import psycopg
from psycopg2.pool import SimpleConnectionPool
from contextlib import contextmanager
from typing import Optional

class SKSRateTracker:
    def __init__(self, key_id: int, number_of_uses_allowed: int, amount_of_time: timedelta, 
                 db_pool: SimpleConnectionPool):
        """Initialize the rate tracker with a key ID and rate limit settings.
        
        Args:
            key_id: The ID of the key to track
            number_of_uses_allowed: Maximum number of uses allowed in the time period
            amount_of_time: Time period for the number of uses allowed
            db_pool: PostgreSQL connection pool
        """
        self.key_id = key_id
        self.db_pool = db_pool
        self.rate_limit_timedelta: Optional[timedelta] = None
        self.rate_limit_uses_allowed: Optional[int] = None
        
        # Create the tracking table if it doesn't exist
        self._create_table()
        self.set_rate_limit(number_of_uses_allowed, amount_of_time)

    @contextmanager
    def _get_db_connection(self):
        """Context manager for database connections from the pool."""
        conn = self.db_pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.db_pool.putconn(conn)

    def _create_table(self):
        """Create the key_usage table if it doesn't exist."""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS key_usage (
            key_id INTEGER NOT NULL,
            used_at TIMESTAMP WITH TIME ZONE NOT NULL,
            PRIMARY KEY (key_id, used_at)
        );
        CREATE INDEX IF NOT EXISTS idx_key_usage_time 
        ON key_usage (key_id, used_at DESC);
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_table_sql)

    def set_rate_limit(self, number_of_uses_allowed: int, amount_of_time: timedelta):
        """Set the rate limit values for this key.
        
        Args:
            number_of_uses_allowed: Maximum number of uses allowed in the time period
            amount_of_time: Time period for the rate limit
        """
        if number_of_uses_allowed <= 0:
            raise ValueError("Number of uses allowed must be positive")
        if amount_of_time <= timedelta():
            raise ValueError("Amount of time must be positive")
            
        self.rate_limit_timedelta = amount_of_time
        self.rate_limit_uses_allowed = number_of_uses_allowed

    def add_use(self):
        """Add a usage instance of this key if there are uses remaining.
        
        Raises:
            RuntimeError: If no uses remaining
            psycopg2.Error: If database operation fails
        """
        if not self.has_uses_remaining():
            raise RuntimeError(f"KeyRateError: Out of uses for key {self.key_id}")
            
        insert_sql = """
        INSERT INTO key_usage (key_id, used_at)
        VALUES (%s, %s);
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(insert_sql, (self.key_id, datetime.now(timezone.utc)))

    def has_uses_remaining(self) -> bool:
        """Check if any uses are still available.
        
        Returns:
            bool: True if uses remain, False otherwise
        """
        return self.uses_remaining() > 0

    def uses_remaining(self) -> int:
        """Check how many key uses are still available.
        
        Returns:
            int: Number of uses remaining in the current time window
        """
        if self.rate_limit_timedelta is None:
            raise RuntimeError("Rate limit not set")
            
        count_sql = """
        SELECT COUNT(*) 
        FROM key_usage 
        WHERE key_id = %s 
        AND used_at > %s;
        """
        window_start = datetime.now(timezone.utc) - self.rate_limit_timedelta
        
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(count_sql, (self.key_id, window_start))
                current_uses = cur.fetchone()[0]
                
        return max(0, self.rate_limit_uses_allowed - current_uses)

    def cleanup_uses(self, age_as_timedelta: timedelta = timedelta(hours=24)):
        """Remove uses that are older than age_as_timedelta.
        
        Args:
            age_as_timedelta: Age threshold for removing records
        """
        if age_as_timedelta <= timedelta():
            raise ValueError("Cleanup age must be positive")
            
        cleanup_sql = """
        DELETE FROM key_usage 
        WHERE key_id = %s 
        AND used_at < %s;
        """
        threshold = datetime.now(timezone.utc) - age_as_timedelta
        
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(cleanup_sql, (self.key_id, threshold))