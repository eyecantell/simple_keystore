import os
from datetime import timedelta
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

    # Use a single shared throttler for all keys
    shared_throttler = SKSRateThrottler(
        api_key_id=0, number_of_uses_allowed=10, amount_of_time=timedelta(seconds=5)
    )

    # Verify initial state for each key
    key_records = ks.get_matching_key_records(name=key_name)
    for record in key_records:
        remaining, _ = shared_throttler.remaining_uses(claim_slot=False, api_key_id=record["id"])
        assert remaining == shared_throttler.rate_limit_uses_allowed, (
            f"Expected key {record['id']} to start with "
            f"{shared_throttler.rate_limit_uses_allowed} uses, but got {remaining} - "
            "this script may have been run too quickly back to back"
        )

    # Test scenario 1: Claim uses from keys 3 and 1, expect key 2 to have most uses
    remaining_tuple = shared_throttler.remaining_uses(claim_slot=True, api_key_id=3)
    assert remaining_tuple == (9, True), (
        f"Failed to claim use for api_key_id 3, expected (9, True) but got {remaining_tuple}"
    )
    remaining_tuple = shared_throttler.remaining_uses(claim_slot=True, api_key_id=1)
    assert remaining_tuple == (9, True), (
        f"Failed to claim use for api_key_id 1, expected (9, True) but got {remaining_tuple}"
    )
    key_with_most = get_key_with_most_uses_remaining(
        key_name=key_name, keystore=ks, throttler=shared_throttler
    )
    assert key_with_most == 2, f"Expected key 2 to have most uses, but got {key_with_most}"

    # Test scenario 2: Claim more uses, expect key 1 to have most uses
    remaining_tuple = shared_throttler.remaining_uses(claim_slot=True, api_key_id=2)
    assert remaining_tuple == (9, True), (
        f"Failed to claim use for api_key_id 2, expected (9, True) but got {remaining_tuple}"
    )
    remaining_tuple = shared_throttler.remaining_uses(claim_slot=True, api_key_id=2)
    assert remaining_tuple == (8, True), (
        f"Failed to claim use for api_key_id 2, expected (8, True) but got {remaining_tuple}"
    )
    remaining_tuple = shared_throttler.remaining_uses(claim_slot=True, api_key_id=3)
    assert remaining_tuple == (8, True), (
        f"Failed to claim use for api_key_id 3, expected (8, True) but got {remaining_tuple}"
    )
    remaining_tuple = shared_throttler.remaining_uses(claim_slot=True, api_key_id=3)
    assert remaining_tuple == (7, True), (
        f"Failed to claim use for api_key_id 3, expected (7, True) but got {remaining_tuple}"
    )
    key_with_most = get_key_with_most_uses_remaining(
        key_name=key_name, keystore=ks, throttler=shared_throttler
    )
    assert key_with_most == 1, f"Expected key 1 to have most uses, but got {key_with_most}"

    # Cleanup
    os.remove(tmp_db)


if __name__ == "__main__":
    test_get_key_with_most_uses_remaining()
