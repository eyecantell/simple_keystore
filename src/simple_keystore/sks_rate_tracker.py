from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from time import sleep
from typing import Optional
import base64
import os
import psycopg

class SKSRateTracker:
    def __init__(self, api_key_id: int, number_of_uses_allowed: int, amount_of_time: timedelta, 
                 db_config: Optional[dict] = None, create_db_if_dne: bool = False):
        """Initialize the rate tracker with a key ID and rate limit settings.
        
        Args:
            api_key_id: The ID of the key to track
            number_of_uses_allowed: Maximum number of uses allowed in the time period
            amount_of_time: Time period for the number of uses allowed
            db_config: Database connection configuration
            create_db_if_dne: Flag to create database if it doesn't exist
        """
        self.api_key_id = api_key_id
        self.rate_limit_timedelta = None
        self.rate_limit_uses_allowed = None
        
        # Default database configuration for Kubernetes
        if db_config is None:
            db_config = {
                'host': 'postgres',  # Service name
                'dbname': 'key_usage_v1',  # Database name
                'user': 'postgres',  # PostgreSQL default user
                'password': base64.b64decode(os.getenv('POSTGRES_PASSWORD')).decode('utf-8')  # Decode the secret
            }

        self.db_config = db_config

        print(f"{db_config=}")

        # Check if database exists, create if it doesn't and flag is set
        if not self.db_exists(db_config):
            if create_db_if_dne:
                self.create_db(db_config)
            else:
                raise RuntimeError(f"Cannot find key usage database {db_config=}")
        
        # Open a connection to the key_usage_v1 database
        self.conn = psycopg.connect(**db_config)
        
        #print(f"{self.conn=}")

        # Create the tracking table if it doesn't exist
        self._create_key_usage_table()

        # Set the rate limit with the passed values
        self.set_rate_limit(number_of_uses_allowed, amount_of_time)

        #print(f"{self=}")


    def create_db(self, db_config: dict = None):
        """Create a new PostgreSQL key rate tracking database."""
        if db_config is None: db_config = self.db_config
        admin_config = db_config.copy()
        admin_config['dbname'] = 'postgres'  # Connect to the default 'postgres' database to create new one

        with psycopg.connect(**admin_config, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(f"CREATE DATABASE {db_config['dbname']};")

    def delete_db(self, db_config: dict = None):
        if db_config is None: db_config = self.db_config
        admin_config = db_config.copy()
        admin_config['dbname'] = 'postgres'
        with psycopg.connect(**admin_config, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(f"DROP DATABASE IF EXISTS {db_config['dbname']};")

    def db_exists(self, db_config : dict = None):
        """Check if the database exists."""
        try:
            if db_config is None: db_config = self.db_config

            admin_config = db_config.copy()
            admin_config['dbname'] = 'postgres'  # Connect to the default 'postgres' database to check for others
            with psycopg.connect(**admin_config) as conn:
                with conn.cursor() as cur:
                    cur.execute(f"SELECT 1 FROM pg_catalog.pg_database WHERE datname = '{db_config['dbname']}';")
                    return cur.fetchone() is not None
        except psycopg.Error:
            # If we can't connect or query, assume the DB doesn't exist or there's an error
            return False

    def __del__(self):
        """Close the database connection when the object is destroyed."""
        if self.conn:
            self.conn.close()

    @contextmanager
    def _get_db_connection(self):
        """Yield the database connection for use."""
        try:
            yield self.conn
        except Exception as e:
            raise e

    def _create_key_usage_table(self):
        """Create the key_usage_v1 table if it doesn't exist."""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS key_usage_v1 (
            api_key_id INTEGER NOT NULL,
            used_at TIMESTAMP WITH TIME ZONE NOT NULL,
            requestor VARCHAR(255),
            PRIMARY KEY (api_key_id, used_at)
        );
        CREATE INDEX IF NOT EXISTS idx_key_usage_time 
        ON key_usage_v1 (api_key_id, used_at DESC);
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_table_sql)
        print("Created key_usage_v1 table")

    def set_rate_limit(self, number_of_uses_allowed: int, amount_of_time: timedelta):
        """Set the rate limit values for this key."""
        if number_of_uses_allowed <= 0:
            raise ValueError("Number of uses allowed must be positive")
        if amount_of_time <= timedelta():
            raise ValueError("Amount of time must be positive")
            
        self.rate_limit_timedelta = amount_of_time
        self.rate_limit_uses_allowed = number_of_uses_allowed

    def add_use(self, time_used: datetime = datetime.now(timezone.utc), retries: int = 3, delay: float = 0.1):
        """Add a usage instance of this key if there are uses remaining."""
        if not self.has_uses_remaining():
            raise RuntimeError(f"KeyRateError: Out of uses for key {self.api_key_id}")

        print(f"orig {time_used=}")

        insert_sql = """
        INSERT INTO key_usage_v1 (api_key_id, used_at)
        VALUES (%s, %s);
        """
        
        for attempt in range(retries):
            try:
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(insert_sql, (self.api_key_id, time_used))
                return  # Exit the method if the insert is successful
            
            except Exception as e:

                 # Rollback the transaction since there was an error
                conn.rollback()

                if attempt < retries - 1:  # not the last attempt
                    sleep(delay)  # Wait before retrying
                    # Increment time used by one microsecond (for cases that time used already existed for this api key)
                    time_used += timedelta(microseconds=1)
                    print(f"updated {time_used=}")
                else:
                    # last attempt failed
                    raise RuntimeError(f"Database error while adding use: {str(e)}") from e

    def has_uses_remaining(self) -> bool:
        """Check if any uses are still available."""
        return self.uses_remaining() > 0

    def uses_remaining(self) -> int:
        """Check how many key uses are still available."""
        if self.rate_limit_timedelta is None:
            raise RuntimeError("Rate limit not set")
            
        count_sql = """
        SELECT COUNT(*) 
        FROM key_usage_v1 
        WHERE api_key_id = %s 
        AND used_at > %s;
        """
        window_start = datetime.now(timezone.utc) - self.rate_limit_timedelta
        
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(count_sql, (self.api_key_id, window_start))
                current_uses = cur.fetchone()[0]
                
        return max(0, self.rate_limit_uses_allowed - current_uses)

    def cleanup_uses(self, age_as_timedelta: timedelta = timedelta(hours=24)):
        """Remove uses that are older than age_as_timedelta."""
        if age_as_timedelta <= timedelta():
            raise ValueError("Cleanup age must be positive")
            
        cleanup_sql = """
        DELETE FROM key_usage_v1 
        WHERE api_key_id = %s 
        AND used_at < %s;
        """
        threshold = datetime.now(timezone.utc) - age_as_timedelta
        
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(cleanup_sql, (self.api_key_id, threshold))