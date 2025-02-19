import pytest
from datetime import datetime, timedelta, timezone
from simple_keystore import SKSRateTracker


@pytest.fixture()  # scope="module")
def rate_tracker():
    test_db_config = {
        "host": "localhost",
        "dbname": "test_sks_rate_tracker_db",
        "user": "developer",
        "password": "developer",
    }
    tracker = SKSRateTracker(
        api_key_id=1,
        number_of_uses_allowed=10,
        amount_of_time=timedelta(seconds=1),
        db_config=test_db_config,
        create_db_if_dne=True,
    )
    yield tracker
    # Cleanup
    tracker.conn.close()
    tracker.delete_db(test_db_config)


def test_create_db(rate_tracker):
    assert rate_tracker.db_exists(rate_tracker.db_config), f"Expected database to be created: {rate_tracker.db_config=}"


def test_delete_db():
    tmp_db_config = {
        "host": "localhost",
        "dbname": "test_delete_db_db",
        "user": "developer",
        "password": "developer",
    }
    tracker = SKSRateTracker(
        api_key_id=1,
        number_of_uses_allowed=10,
        amount_of_time=timedelta(seconds=1),
        db_config=tmp_db_config,
        create_db_if_dne=True,
    )
    tracker.conn.close()
    tracker.delete_db(tracker.db_config)
    assert not tracker.db_exists(tracker.db_config), f"Expected database to be deleted: {tracker.db_config=}"


def test_add_use(rate_tracker):
    rate_tracker.add_use()
    assert rate_tracker.uses_remaining() == 9, "Used one, should have 9 uses remaining"


def test_exceed_limit(rate_tracker):
    start_datetime = datetime.now()
    for _ in range(rate_tracker.rate_limit_uses_allowed):
        rate_tracker.add_use()
    if (datetime.now() - start_datetime) > rate_tracker.rate_limit_timedelta:
        raise RuntimeError("Adding uses taking too long - will need to adjust test_exceed_limit")

    assert not rate_tracker.has_uses_remaining(), "Expected to be out of uses"

    with pytest.raises(RuntimeError, match="Out of uses for key"):
        rate_tracker.add_use()


def test_add_use_from_two_trackers(rate_tracker):
    """Use two different trackers to add uses. Make sure both reflect that multiple uses were added"""
    rate_tracker.add_use()
    assert rate_tracker.uses_remaining() == rate_tracker.rate_limit_uses_allowed - 1, (
        f"Expected to have {rate_tracker.rate_limit_uses_allowed - 1} uses remaining after using one, but got {rate_tracker.uses_remaining()}"
    )
    second_rate_tracker = SKSRateTracker(
        api_key_id=rate_tracker.api_key_id,
        number_of_uses_allowed=10,
        amount_of_time=timedelta(seconds=1),
        db_config=rate_tracker.db_config,
    )
    second_rate_tracker.add_use()
    assert rate_tracker.uses_remaining() == rate_tracker.rate_limit_uses_allowed - 2, (
        f"Expected rate_tracker to have {rate_tracker.rate_limit_uses_allowed - 2} uses remaining after using two, but got {rate_tracker.uses_remaining()}"
    )
    assert second_rate_tracker.uses_remaining() == second_rate_tracker.rate_limit_uses_allowed - 2, (
        f"Expected second_rate_tracker to have {second_rate_tracker.rate_limit_uses_allowed - 2} uses remaining after using two, but got {rate_tracker.second_rate_tracker()}"
    )


def test_rate_limit_expiry(rate_tracker):
    """Test that uses expire after the rate limit time window."""
    import time

    # Use half the allowed uses
    uses_to_add = rate_tracker.rate_limit_uses_allowed // 2
    for _ in range(uses_to_add):
        rate_tracker.add_use()

    # Verify we've used the expected amount
    expected_remaining = rate_tracker.rate_limit_uses_allowed - uses_to_add
    assert rate_tracker.uses_remaining() == expected_remaining, (
        f"Expected {expected_remaining} uses remaining, got {rate_tracker.uses_remaining()}"
    )

    # Wait slightly longer than the rate limit window
    wait_time = rate_tracker.rate_limit_timedelta.total_seconds() * 1.1
    time.sleep(wait_time)

    # After waiting, all uses should be expired
    assert rate_tracker.uses_remaining() == rate_tracker.rate_limit_uses_allowed, (
        "Expected all uses to expire after waiting"
    )


def test_cleanup_uses(rate_tracker):
    """Test that cleanup_uses properly removes old usage records."""
    # Add some uses
    rate_tracker.add_use()
    rate_tracker.add_use()

    # Get current count of uses
    count_sql = """
    SELECT COUNT(*) FROM key_usage_v1 WHERE api_key_id = %s;
    """
    with rate_tracker.conn.cursor() as cur:
        cur.execute(count_sql, (rate_tracker.api_key_id,))
        initial_count = cur.fetchone()[0]

    # Clean up uses with a very short age (cleanup everything)
    cleanup_age = timedelta(microseconds=1)
    rate_tracker.cleanup_uses(cleanup_age)

    # Verify counts after cleanup
    with rate_tracker.conn.cursor() as cur:
        cur.execute(count_sql, (rate_tracker.api_key_id,))
        after_cleanup_count = cur.fetchone()[0]

    assert after_cleanup_count == 0, f"Expected all uses to be cleaned up, but found {after_cleanup_count} remaining"


def test_multiple_api_keys():
    """Test that different API keys are tracked separately."""
    test_db_config = {
        "host": "localhost",
        "dbname": "test_multi_key_db",
        "user": "developer",
        "password": "developer",
    }

    # Create two trackers with different API key IDs
    tracker1 = SKSRateTracker(
        api_key_id=101,
        number_of_uses_allowed=5,
        amount_of_time=timedelta(seconds=5),
        db_config=test_db_config,
        create_db_if_dne=True,
    )

    tracker2 = SKSRateTracker(
        api_key_id=102,
        number_of_uses_allowed=5,
        amount_of_time=timedelta(seconds=5),
        db_config=test_db_config,
    )

    try:
        # Add uses for first key
        tracker1.add_use()
        tracker1.add_use()

        # Add uses for second key
        tracker2.add_use()

        # Verify each tracker shows correct remaining uses
        assert tracker1.uses_remaining() == 3, (
            f"Tracker1 should have 3 uses remaining but has {tracker1.uses_remaining()}"
        )
        assert tracker2.uses_remaining() == 4, (
            f"Tracker2 should have 4 uses remaining but has {tracker2.uses_remaining()}"
        )

    finally:
        # Cleanup
        tracker1.conn.close()
        tracker2.conn.close()
        tracker1.delete_db(test_db_config)


def test_invalid_rate_limits():
    """Test validation of rate limit parameters."""
    test_db_config = {
        "host": "localhost",
        "dbname": "test_validation_db",
        "user": "developer",
        "password": "developer",
    }

    tracker = SKSRateTracker(
        api_key_id=1,
        number_of_uses_allowed=10,
        amount_of_time=timedelta(seconds=1),
        db_config=test_db_config,
        create_db_if_dne=True,
    )

    try:
        # Test negative uses allowed
        with pytest.raises(ValueError, match="Number of uses allowed must be positive"):
            tracker.set_rate_limit(-1, timedelta(seconds=1))

        # Test zero uses allowed
        with pytest.raises(ValueError, match="Number of uses allowed must be positive"):
            tracker.set_rate_limit(0, timedelta(seconds=1))

        # Test negative time window
        with pytest.raises(ValueError, match="Amount of time must be positive"):
            tracker.set_rate_limit(10, timedelta(seconds=-1))

        # Test zero time window
        with pytest.raises(ValueError, match="Amount of time must be positive"):
            tracker.set_rate_limit(10, timedelta(seconds=0))

    finally:
        # Cleanup
        tracker.conn.close()
        tracker.delete_db(test_db_config)


def test_concurrent_usage_timestamps():
    """Test handling of concurrent usage timestamps."""
    test_db_config = {
        "host": "localhost",
        "dbname": "test_concurrent_db",
        "user": "developer",
        "password": "developer",
    }

    tracker = SKSRateTracker(
        api_key_id=1,
        number_of_uses_allowed=10,
        amount_of_time=timedelta(seconds=10),
        db_config=test_db_config,
        create_db_if_dne=True,
    )

    try:
        # Create a fixed timestamp
        fixed_time = datetime.now(timezone.utc)

        # Add use with the fixed timestamp
        tracker.add_use(time_used=fixed_time)

        # Try to add another use with the same timestamp
        # Should succeed due to retry mechanism
        tracker.add_use(time_used=fixed_time)

        # Verify two uses were recorded
        assert tracker.uses_remaining() == 8, (
            f"Expected 8 uses remaining after adding 2, but got {tracker.uses_remaining()}"
        )

    finally:
        # Cleanup
        tracker.conn.close()
        tracker.delete_db(test_db_config)
