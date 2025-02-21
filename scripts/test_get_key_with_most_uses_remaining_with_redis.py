import os
from datetime import timedelta
from dateutil.relativedelta import relativedelta
from simple_keystore import SimpleKeyStore, SKSRateThrottler, get_key_with_most_uses_remaining


def test_get_key_with_most_uses_remaining():
    """Test function to verify the behavior of get_key_with_most_uses_remaining."""
    # Setup
    tmp_db = "tmp_get_key_with_most_uses_remaining.db"
    key_name = "mykeyname"

    # Clean up existing temporary database
    if os.path.isfile(tmp_db):
        os.remove(tmp_db)

    # Initialize keystore and add test keys
    ks = SimpleKeyStore(tmp_db)
    ks.add_key(key_name, "aaaa", active=True)
    ks.add_key(key_name, "bbbb", active=True)
    ks.add_key(key_name, "cccc", active=True)

    # Get key records and initialize throttlers
    key_records = ks.get_matching_key_records(name=key_name)
    throttler_by_id = {
        record["id"]: SKSRateThrottler(
            api_key_id=record["id"], number_of_uses_allowed=10, amount_of_time=timedelta(seconds=5)
        )
        for record in key_records
    }

    # Verify initial state of throttlers
    for throttler in throttler_by_id.values():
        remaining, _ = throttler.remaining_uses(claim_slot=False)
        assert remaining == throttler.rate_limit_uses_allowed, (
            f"Expected throttler {throttler.api_key_id} to start with "
            f"{throttler.rate_limit_uses_allowed} uses, but got {remaining} - "
            "this script may have been run too quickly back to back"
        )

    # Test scenario 1: Claim uses from keys 0 and 1, expect key 2 to have most uses
    remaining_tuple = throttler_by_id[3].remaining_uses(claim_slot=True)
    assert remaining_tuple == (9, True), (
        f"Failed to claim use for api_key_id 3, expected (9, True) but got {remaining_tuple}"
    )
    remaining_tuple = throttler_by_id[1].remaining_uses(claim_slot=True)
    assert remaining_tuple == (9, True), (
        f"Failed to claim use for api_key_id 1, expected (9, True) but got {remaining_tuple}"
    )
    key_with_most = get_key_with_most_uses_remaining(key_name=key_name, keystore=ks)
    assert key_with_most == 2, f"Expected key 2 to have most uses, but got {key_with_most}"

    # Test scenario 2: Claim more uses, expect key 1 to have most uses
    remaining_tuple = throttler_by_id[2].remaining_uses(claim_slot=True)
    assert remaining_tuple == (9, True), (
        f"Failed to claim use for api_key_id 2, expected (9, True) but got {remaining_tuple}"
    )
    remaining_tuple = throttler_by_id[2].remaining_uses(claim_slot=True)
    assert remaining_tuple == (8, True), (
        f"Failed to claim use for api_key_id 2, expected (8, True) but got {remaining_tuple}"
    )
    remaining_tuple = throttler_by_id[3].remaining_uses(claim_slot=True)
    assert remaining_tuple == (8, True), (
        f"Failed to claim use for api_key_id 3, expected (8, True) but got {remaining_tuple}"
    )
    remaining_tuple = throttler_by_id[3].remaining_uses(claim_slot=True)
    assert remaining_tuple == (7, True), (
        f"Failed to claim use for api_key_id 3, expected (7, True) but got {remaining_tuple}"
    )
    key_with_most = get_key_with_most_uses_remaining(key_name=key_name, keystore=ks)
    assert key_with_most == 1, f"Expected key 1 to have most uses, but got {key_with_most}"

    # Cleanup
    os.remove(tmp_db)


if __name__ == "__main__":
    test_get_key_with_most_uses_remaining()
