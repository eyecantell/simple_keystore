from datetime import datetime, timedelta, timezone
from simple_keystore import SKSRateTracker
from time import sleep
from typing import Optional
from uuid import uuid4, UUID
import psycopg


class SKSRateThrottler:
    USE_REQUESTS_TABLE_NAME = "key_use_requests_v1"

    def __init__(
        self,
        api_key_id: int,
        number_of_uses_allowed: int,
        amount_of_time: timedelta,
        db_config: Optional[dict] = None,
        create_db_if_dne: bool = False,
        requestor_name: str = None,
        requestor_uuid: UUID = None,
    ):
        """Initialize the rate throttler with a key ID and rate limit settings."""

        # Note SKSRateTracker will make sure our db exists
        self.tracker = SKSRateTracker(
            api_key_id=api_key_id,
            number_of_uses_allowed=number_of_uses_allowed,
            amount_of_time=amount_of_time,
            db_config=db_config,
            create_db_if_dne=create_db_if_dne,
        )

        self.db_config = self.tracker.db_config

        print(f"SKSRateThrottler {self.db_config=}")

        # Open a connection to the database with autocommit=True for DDL operations
        self.conn = psycopg.connect(**self.db_config, autocommit=True)
        self.requestor_name = requestor_name
        self.requestor_uuid: UUID = (
            requestor_uuid or uuid4()
        )  # Will be used to differentiate requests from among different throttler instances

    def _create_use_requests_table(self):
        """Create the USE_REQUESTS_TABLE_NAME table if it doesn't exist."""
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {self.USE_REQUESTS_TABLE_NAME} (
            api_key_id INTEGER NOT NULL,
            requested_at TIMESTAMP WITH TIME ZONE NOT NULL,
            requestor_name VARCHAR(63),
            requestor_uuid VARCHAR(63),
            PRIMARY KEY (api_key_id, requested_at, requestor_uuid)
        );
        CREATE INDEX IF NOT EXISTS idx_key_usage_time
        ON {self.USE_REQUESTS_TABLE_NAME} (api_key_id, requested_at, requestor_uuid);
        """
        with self.conn.cursor() as cur:
            cur.execute(create_table_sql)
            # No need for commit as autocommit=True during table creation
        print(f"Created {self.USE_REQUESTS_TABLE_NAME=} table")

    def add_use_request(self, requestor_name: str = None, retries: int = 3, delay: float = 0.1):
        """Add a key usage request"""

        time_requested = datetime.now(timezone.utc)
        print(f"orig {time_requested=}")

        if requestor_name is None:
            requestor_name = self.requestor_name

        insert_sql = f"""
        INSERT INTO {self.USE_REQUESTS_TABLE_NAME} (api_key_id, requested_at, requestor_name, requestor_uuid)
        VALUES (%s, %s, %s, %s);
        """

        for attempt in range(retries):
            try:
                with self.conn.cursor() as cur:
                    cur.execute(
                        insert_sql, (self.tracker.api_key_id, time_requested, requestor_name, self.requestor_uuid)
                    )
                # Commit the insert
                self.conn.commit()
                return  # Exit the method if the insert is successful

            except Exception as e:
                # Rollback the transaction since there was an error
                self.conn.rollback()

                if attempt < retries - 1:  # not the last attempt
                    sleep(delay)  # Wait before retrying
                    # Increment time requested by one microsecond (for cases that time requested already existed for this api key)
                    time_requested += timedelta(microseconds=1)
                    print(f"updated {time_requested=}")
                else:
                    # last attempt failed
                    raise RuntimeError(f"Database error while adding use: {str(e)}") from e

        pass

    def block_until_next_use_available():
        pass
