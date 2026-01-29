import importlib
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from simple_keystore import SimpleKeyStore, SKSRateThrottler
from simple_keystore.get_key_with_most_uses_remaining import get_key_with_most_uses_remaining

# Import the actual module (not the re-exported function from __init__.py)
_gkwmur_module = importlib.import_module("simple_keystore.get_key_with_most_uses_remaining")

TEST_KEYSTORE_NAME = "keystore_for_tests.db"


@pytest.fixture
def ks():
    keystore = SimpleKeyStore(TEST_KEYSTORE_NAME)
    yield keystore
    keystore.close_connection()


@pytest.fixture
def key_name():
    return "test_get_key_with_most_uses_remaining"


@pytest.fixture
def setup_keys(ks, key_name):
    """Create test keys and clean up after."""
    ks.delete_records_with_name(key_name)
    yield
    ks.delete_records_with_name(key_name)


def test_no_usable_keys_returns_none(ks, key_name, setup_keys, fake_redis):
    """No usable keys should return None."""
    throttler = SKSRateThrottler(
        api_key_id=0, number_of_uses_allowed=10, amount_of_time=timedelta(seconds=60), redis_client=fake_redis
    )
    result = get_key_with_most_uses_remaining(key_name=key_name, keystore=ks, throttler=throttler)
    assert result is None


def test_single_usable_key_returns_its_id(ks, key_name, setup_keys, fake_redis):
    """Single usable key should return its ID."""
    tomorrow = datetime.today() + timedelta(days=1)
    new_id = ks.add_key(
        name=key_name, unencrypted_key="single_key_value", expiration_in_sse=int(tomorrow.timestamp())
    )

    throttler = SKSRateThrottler(
        api_key_id=0, number_of_uses_allowed=10, amount_of_time=timedelta(seconds=60), redis_client=fake_redis
    )
    result = get_key_with_most_uses_remaining(key_name=key_name, keystore=ks, throttler=throttler)
    assert result == new_id


def test_multiple_keys_returns_most_remaining(ks, key_name, setup_keys, fake_redis):
    """With multiple keys and different usage, should return the one with most remaining."""
    tomorrow = datetime.today() + timedelta(days=1)
    id1 = ks.add_key(name=key_name, unencrypted_key="key_val_1", expiration_in_sse=int(tomorrow.timestamp()))
    id2 = ks.add_key(name=key_name, unencrypted_key="key_val_2", expiration_in_sse=int(tomorrow.timestamp()))

    throttler = SKSRateThrottler(
        api_key_id=0, number_of_uses_allowed=10, amount_of_time=timedelta(seconds=60), redis_client=fake_redis
    )

    # Use up 5 slots for key id1
    for _ in range(5):
        throttler.remaining_uses(claim_slot=True, api_key_id=id1)

    # Use up 2 slots for key id2
    for _ in range(2):
        throttler.remaining_uses(claim_slot=True, api_key_id=id2)

    result = get_key_with_most_uses_remaining(key_name=key_name, keystore=ks, throttler=throttler)
    assert result == id2  # id2 has 8 remaining vs id1's 5


def test_with_provided_throttler(ks, key_name, setup_keys, fake_redis):
    """When a throttler is provided, it should be reused with per-call api_key_id."""
    tomorrow = datetime.today() + timedelta(days=1)
    new_id = ks.add_key(
        name=key_name, unencrypted_key="throttler_key", expiration_in_sse=int(tomorrow.timestamp())
    )

    throttler = SKSRateThrottler(
        api_key_id=0, number_of_uses_allowed=10, amount_of_time=timedelta(seconds=60), redis_client=fake_redis
    )

    result = get_key_with_most_uses_remaining(key_name=key_name, keystore=ks, throttler=throttler)
    assert result == new_id


def test_without_throttler_creates_per_key(ks, key_name, setup_keys):
    """When no throttler is provided, a new SKSRateThrottler is created per key."""
    tomorrow = datetime.today() + timedelta(days=1)
    new_id = ks.add_key(
        name=key_name, unencrypted_key="no_throttler_key", expiration_in_sse=int(tomorrow.timestamp())
    )

    # Mock SKSRateThrottler so we don't need real Redis
    mock_throttler_instance = MagicMock()
    mock_throttler_instance.remaining_uses.return_value = (10, False)

    with patch.object(
        _gkwmur_module, "SKSRateThrottler",
        return_value=mock_throttler_instance,
    ) as mock_class:
        result = get_key_with_most_uses_remaining(key_name=key_name, keystore=ks, throttler=None)
        assert result == new_id
        mock_class.assert_called_once()
        mock_throttler_instance.remaining_uses.assert_called_once_with(claim_slot=False)


def test_verbose_output(ks, key_name, setup_keys, fake_redis, capsys):
    """Verbose mode should print remaining uses for each key."""
    tomorrow = datetime.today() + timedelta(days=1)
    ks.add_key(name=key_name, unencrypted_key="verbose_key", expiration_in_sse=int(tomorrow.timestamp()))

    throttler = SKSRateThrottler(
        api_key_id=0, number_of_uses_allowed=10, amount_of_time=timedelta(seconds=60), redis_client=fake_redis
    )

    get_key_with_most_uses_remaining(key_name=key_name, keystore=ks, throttler=throttler, verbose=True)
    captured = capsys.readouterr()
    assert "uses remaining" in captured.out
    assert key_name in captured.out


def test_ties_deterministic(ks, key_name, setup_keys, fake_redis):
    """When two keys have equal remaining uses, behavior should be deterministic (first encountered wins)."""
    tomorrow = datetime.today() + timedelta(days=1)
    id1 = ks.add_key(name=key_name, unencrypted_key="tie_key_1", expiration_in_sse=int(tomorrow.timestamp()))
    id2 = ks.add_key(name=key_name, unencrypted_key="tie_key_2", expiration_in_sse=int(tomorrow.timestamp()))

    throttler = SKSRateThrottler(
        api_key_id=0, number_of_uses_allowed=10, amount_of_time=timedelta(seconds=60), redis_client=fake_redis
    )

    # Both keys have equal uses (0 used). The first key encountered should win.
    result = get_key_with_most_uses_remaining(key_name=key_name, keystore=ks, throttler=throttler)
    # With equal remaining, the first key processed (id1) gets max_uses set first,
    # and id2 ties but does not surpass (> not >=), so id1 wins.
    assert result == id1
