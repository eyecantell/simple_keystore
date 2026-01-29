from simple_keystore import SimpleKeyStore, SKSRateThrottler
from datetime import timedelta


def get_key_with_most_uses_remaining(
    key_name: str,
    keystore: SimpleKeyStore,
    throttler: SKSRateThrottler | None = None,
    verbose: bool = False,
) -> int | None:
    """
    Retrieve the ID of the key with the most remaining uses for a given key name.

    Args:
        key_name (str): The name of the key to search for
        keystore (SimpleKeyStore): The keystore instance to query
        throttler (SKSRateThrottler | None): An existing throttler to reuse. When provided,
            api_key_id is passed per-call. When None, a new throttler is created per key
            with hardcoded defaults (preserves backward compatibility).
        verbose (bool): If True, print remaining uses for each key (default: False)

    Returns:
        int | None: The ID of the key with the most remaining uses, or None if no usable keys found
    """
    # Fetch all active key records matching the given name
    key_records = keystore.get_matching_key_records(
        name=key_name,
        active=True,
    )

    # Track the key with maximum remaining uses
    max_key_id: int | None = None
    max_uses: int = -1

    # Evaluate each key record
    for record in key_records:
        if not record["usable"]:
            continue

        if throttler is not None:
            # Reuse provided throttler with per-call api_key_id
            remaining, _ = throttler.remaining_uses(claim_slot=False, api_key_id=record["id"])
        else:
            # Create a new throttler per key (backward-compatible default)
            per_key_throttler = SKSRateThrottler(
                api_key_id=record["id"], number_of_uses_allowed=10, amount_of_time=timedelta(seconds=5)
            )
            remaining, _ = per_key_throttler.remaining_uses(claim_slot=False)

        # Optional verbose output
        if verbose:
            print(f"Key '{key_name}' (ID: {record['id']}) has {remaining} uses remaining")

        # Update max if this key has more remaining uses
        if remaining > max_uses:
            max_key_id = record["id"]
            max_uses = remaining

    return max_key_id
