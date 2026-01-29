import pytest
from unittest.mock import patch
from datetime import datetime, timedelta
from simple_keystore.manage_simple_keys import get_input, get_expiration_seconds_from_input


class TestGetInput:
    def test_returns_user_input(self):
        """get_input returns the user's typed value."""
        with patch("builtins.input", return_value="hello"):
            result = get_input("Enter something")
            assert result == "hello"

    def test_returns_default_when_empty(self):
        """get_input returns default when user enters empty string."""
        with patch("builtins.input", return_value=""):
            result = get_input("Enter something", default="fallback")
            assert result == "fallback"

    def test_loops_on_required_until_nonempty(self):
        """get_input keeps prompting until non-empty value for required fields."""
        with patch("builtins.input", side_effect=["", "", "finally"]):
            result = get_input("Enter something", required=True)
            assert result == "finally"


class TestGetExpirationSecondsFromInput:
    def test_integer_days_input(self):
        """Integer input is interpreted as number of days from now."""
        with patch("builtins.input", return_value="30"):
            expiration_sse, expiration_input = get_expiration_seconds_from_input(default=None)
            assert expiration_input == "30"
            # The SSE should be roughly 30 days from now
            expected = datetime.now() + timedelta(days=30)
            assert abs(expiration_sse - int(expected.timestamp())) < 5

    def test_date_input(self):
        """YYYY-MM-DD input is parsed as a specific date."""
        with patch("builtins.input", return_value="2025-06-15"):
            expiration_sse, expiration_input = get_expiration_seconds_from_input(default=None)
            assert expiration_input == "2025-06-15"
            expected = datetime.strptime("2025-06-15", "%Y-%m-%d")
            assert expiration_sse == int(expected.timestamp())

    def test_invalid_input_returns_none_tuple(self, capsys):
        """Invalid input (not days or date) returns (None, None) and prints error."""
        with patch("builtins.input", return_value="foobar"):
            result = get_expiration_seconds_from_input(default=None)
            assert result == (None, None)
            captured = capsys.readouterr()
            assert "Invalid expiration input" in captured.out

    def test_empty_input_returns_none_tuple(self):
        """Empty input returns (None, None)."""
        with patch("builtins.input", return_value=""):
            result = get_expiration_seconds_from_input(default=None)
            assert result == (None, None)
