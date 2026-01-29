import os
import pytest
from unittest.mock import patch, MagicMock
from simple_keystore import SimpleKeyStore


class TestGetSimpleKeystoreKey:
    def test_env_var_set_returns_env_var(self):
        """When SIMPLE_KEYSTORE_KEY env var is set, it should be returned."""
        with patch.dict(os.environ, {"SIMPLE_KEYSTORE_KEY": "my-secret-key"}):
            ks = SimpleKeyStore.__new__(SimpleKeyStore)
            result = ks.get_simple_keystore_key()
            assert result == "my-secret-key"

    def test_env_var_empty_netrc_has_key(self):
        """When env var is empty and .netrc has the key, return the netrc value."""
        mock_netrc_instance = MagicMock()
        mock_netrc_instance.authenticators.return_value = ("user", "account", "netrc-password")

        with patch.dict(os.environ, {"SIMPLE_KEYSTORE_KEY": ""}, clear=False):
            with patch("netrc.netrc", return_value=mock_netrc_instance):
                ks = SimpleKeyStore.__new__(SimpleKeyStore)
                result = ks.get_simple_keystore_key()
                assert result == "netrc-password"

    def test_env_var_unset_netrc_missing_raises(self):
        """When env var is unset and .netrc file is missing, should raise ValueError."""
        with patch.dict(os.environ, {}, clear=True):
            # Preserve PATH so subprocess can still function
            with patch("netrc.netrc", side_effect=FileNotFoundError("~/.netrc not found")):
                ks = SimpleKeyStore.__new__(SimpleKeyStore)
                with pytest.raises(ValueError, match="Could not retrieve SIMPLE_KEYSTORE_KEY"):
                    ks.get_simple_keystore_key()

    def test_env_var_unset_netrc_no_matching_entry_raises(self):
        """When env var is unset and .netrc has no SIMPLE_KEYSTORE_KEY entry, should raise ValueError."""
        mock_netrc_instance = MagicMock()
        mock_netrc_instance.authenticators.return_value = None

        with patch.dict(os.environ, {}, clear=True):
            with patch("netrc.netrc", return_value=mock_netrc_instance):
                ks = SimpleKeyStore.__new__(SimpleKeyStore)
                with pytest.raises(ValueError):
                    ks.get_simple_keystore_key()

    def test_netrc_loose_permissions_emits_warning(self, tmp_path):
        """On non-Windows, .netrc with group/world-readable permissions should emit a warning."""
        mock_netrc_instance = MagicMock()
        mock_netrc_instance.authenticators.return_value = ("user", "account", "netrc-key")

        # Create a temporary .netrc file with loose permissions
        netrc_file = tmp_path / ".netrc"
        netrc_file.write_text("machine SIMPLE_KEYSTORE_KEY password netrc-key")
        netrc_file.chmod(0o644)  # group+world readable

        with patch.dict(os.environ, {}, clear=True):
            with patch("netrc.netrc", return_value=mock_netrc_instance):
                with patch("os.path.expanduser", return_value=str(netrc_file)):
                    with patch("platform.system", return_value="Linux"):
                        ks = SimpleKeyStore.__new__(SimpleKeyStore)
                        with pytest.warns(UserWarning, match="insecure permissions"):
                            ks.get_simple_keystore_key()

    def test_netrc_on_windows_no_permission_warning(self):
        """On Windows, no permission warning should be emitted even with loose permissions."""
        mock_netrc_instance = MagicMock()
        mock_netrc_instance.authenticators.return_value = ("user", "account", "netrc-key")

        with patch.dict(os.environ, {}, clear=True):
            with patch("netrc.netrc", return_value=mock_netrc_instance):
                with patch("platform.system", return_value="Windows"):
                    ks = SimpleKeyStore.__new__(SimpleKeyStore)
                    # Should not warn on Windows
                    import warnings

                    with warnings.catch_warnings():
                        warnings.simplefilter("error")
                        result = ks.get_simple_keystore_key()
                        assert result == "netrc-key"
