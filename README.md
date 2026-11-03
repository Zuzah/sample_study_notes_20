# sample_study_notes_20
KYC/AML Studies

tests/services/test_sftp_connection_service.py:

```python
import pytest

from app.services.delivery_service import DeliveryConfigError
from app.services.sftp_connection_service import (
    SFTPConnectionSettings,
    SFTPConnectionService,
)


def _fake_key_path(tmp_path, name="key"):
    """tmp_path-based, not a string literal - avoids tripping GitGuardian."""
    return str(tmp_path / name)


def test_get_raises_for_unknown_connection_name():
    with pytest.raises(KeyError):
        SFTPConnectionService.get("DoesNotExist")


def test_get_resolves_real_connection_from_prefixed_env_vars(monkeypatch, tmp_path):
    key_path = _fake_key_path(tmp_path)
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_HOST", "lvappi01908.cloud.bns")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_USERNAME", "sftpuser")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_PRIVATE_KEY", key_path)
    monkeypatch.setenv(
        "SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER", "./ClientCentralDataFenergo"
    )

    result = SFTPConnectionService.get("ClientCentralData")

    assert result.host == "lvappi01908.cloud.bns"
    assert result.port == 22
    assert result.username == "sftpuser"
    assert result.private_key_path == key_path
    assert result.remote_folder == "./ClientCentralDataFenergo"
    assert result.marker_remote_folder is None


def test_get_uses_default_port_when_unset(monkeypatch, tmp_path):
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_HOST", "host")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_USERNAME", "user")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_PRIVATE_KEY", _fake_key_path(tmp_path))
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER", "./folder")
    monkeypatch.delenv("SFTP_CLIENTCENTRALDATA_PORT", raising=False)

    assert SFTPConnectionService.get("ClientCentralData").port == 22


def test_get_respects_explicit_port_override(monkeypatch, tmp_path):
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_HOST", "host")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_USERNAME", "user")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_PRIVATE_KEY", _fake_key_path(tmp_path))
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER", "./folder")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_PORT", "2222")

    assert SFTPConnectionService.get("ClientCentralData").port == 2222


def test_get_falls_back_to_global_known_hosts_path_when_unset(monkeypatch, tmp_path):
    from app.core.config import settings

    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_HOST", "host")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_USERNAME", "user")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_PRIVATE_KEY", _fake_key_path(tmp_path))
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER", "./folder")
    monkeypatch.delenv("SFTP_CLIENTCENTRALDATA_KNOWN_HOSTS", raising=False)

    result = SFTPConnectionService.get("ClientCentralData")

    assert result.known_hosts_path == settings.known_hosts_path


def test_get_respects_explicit_known_hosts_path_override(monkeypatch, tmp_path):
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_HOST", "host")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_USERNAME", "user")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_PRIVATE_KEY", _fake_key_path(tmp_path))
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER", "./folder")
    custom_path = str(tmp_path / "custom_known_hosts")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_KNOWN_HOSTS", custom_path)

    result = SFTPConnectionService.get("ClientCentralData")

    assert str(result.known_hosts_path) == custom_path


def test_get_resolves_reg_central_connection_from_prefixed_env_vars(
    monkeypatch, tmp_path
):
    key_path = _fake_key_path(tmp_path, "reg_central_key")
    monkeypatch.setenv("SFTP_REGCENTRAL_HOST", "lvappi03337.cloud.bns")
    monkeypatch.setenv("SFTP_REGCENTRAL_USERNAME", "fenergo2rcp")
    monkeypatch.setenv("SFTP_REGCENTRAL_PRIVATE_KEY", key_path)
    monkeypatch.setenv(
        "SFTP_REGCENTRAL_REMOTE_FOLDER", "/opt/bns/rcp/feed/refdata/fenergo"
    )

    result = SFTPConnectionService.get("RegCentral")

    assert result.host == "lvappi03337.cloud.bns"
    assert result.port == 22
    assert result.username == "fenergo2rcp"
    assert result.private_key_path == key_path
    assert result.remote_folder == "/opt/bns/rcp/feed/refdata/fenergo"


@pytest.mark.parametrize(
    "missing_var",
    [
        "SFTP_CLIENTCENTRALDATA_HOST",
        "SFTP_CLIENTCENTRALDATA_USERNAME",
        "SFTP_CLIENTCENTRALDATA_PRIVATE_KEY",
        "SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER",
    ],
)
def test_get_raises_delivery_config_error_when_a_required_field_is_missing(
    monkeypatch, tmp_path, missing_var
):
    required = {
        "SFTP_CLIENTCENTRALDATA_HOST": "host",
        "SFTP_CLIENTCENTRALDATA_USERNAME": "user",
        "SFTP_CLIENTCENTRALDATA_PRIVATE_KEY": _fake_key_path(tmp_path),
        "SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER": "./folder",
    }
    for name, value in required.items():
        if name == missing_var:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)

    with pytest.raises(DeliveryConfigError):
        SFTPConnectionService.get("ClientCentralData")


def test_get_resolves_edl_connection_including_marker_remote_folder(
    monkeypatch, tmp_path
):
    """EDL is the one connection with a distinct remote folder for its marker
    (Fircosoft manifest) - .../b8fb/ for the data file, .../b8fb/marker/ for the
    manifest. See docs/decisions.md for why .../b8fb/metadata/ is deliberately
    left unwired (not yet confirmed what it's for)."""
    monkeypatch.setenv(
        "SFTP_EDL_HOST", "sdusvrbi814.scglobaluat.aduat.scotiacapital.com"
    )
    monkeypatch.setenv("SFTP_EDL_USERNAME", "edlu_b8fb_sftpid")
    monkeypatch.setenv("SFTP_EDL_PRIVATE_KEY", _fake_key_path(tmp_path, "edl_key"))
    monkeypatch.setenv("SFTP_EDL_REMOTE_FOLDER", "../../../landing1/gbm/b8fb/")
    monkeypatch.setenv(
        "SFTP_EDL_MARKER_REMOTE_FOLDER", "../../../landing1/gbm/b8fb/marker/"
    )

    result = SFTPConnectionService.get("EDL")

    assert result.host == "sdusvrbi814.scglobaluat.aduat.scotiacapital.com"
    assert result.username == "edlu_b8fb_sftpid"
    assert result.remote_folder == "../../../landing1/gbm/b8fb/"
    assert result.marker_remote_folder == "../../../landing1/gbm/b8fb/marker/"


def test_marker_remote_folder_defaults_to_none_when_unset(monkeypatch, tmp_path):
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_HOST", "host")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_USERNAME", "user")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_PRIVATE_KEY", _fake_key_path(tmp_path))
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER", "./folder")
    monkeypatch.delenv("SFTP_CLIENTCENTRALDATA_MARKER_REMOTE_FOLDER", raising=False)

    assert SFTPConnectionService.get("ClientCentralData").marker_remote_folder is None


@pytest.mark.parametrize("connection_name", ["EDL", "TENXCCD", "CCD", "DUCO", "TMX"])
def test_new_connections_are_registered(connection_name, monkeypatch):
    """Registered (no KeyError) even with no real secrets yet - TBD per
    docs/decisions.md, pending another team. DeliveryConfigError (missing HOST,
    the first required field) proves the name is in the registry without needing
    any real/fake secret value."""
    for field in (
        "HOST",
        "USERNAME",
        "PRIVATE_KEY",
        "REMOTE_FOLDER",
        "PORT",
        "KNOWN_HOSTS",
        "MARKER_REMOTE_FOLDER",
    ):
        monkeypatch.delenv(f"SFTP_{connection_name}_{field}", raising=False)

    with pytest.raises(DeliveryConfigError):
        SFTPConnectionService.get(connection_name)


def test_duco_uses_non_default_port(monkeypatch, tmp_path):
    """SFTP_DUCO is the one new connection on a non-standard port (2222)."""
    monkeypatch.setenv("SFTP_DUCO_HOST", "pymthwy-transfer-uat.bns")
    monkeypatch.setenv("SFTP_DUCO_USERNAME", "FENERGODUCO")
    monkeypatch.setenv("SFTP_DUCO_PRIVATE_KEY", _fake_key_path(tmp_path, "duco_key"))
    monkeypatch.setenv("SFTP_DUCO_REMOTE_FOLDER", ".")
    monkeypatch.setenv("SFTP_DUCO_PORT", "2222")

    assert SFTPConnectionService.get("DUCO").port == 2222


@pytest.mark.parametrize("connection_name", ["DUCO", "TMX"])
def test_duco_and_tmx_use_dot_for_root_directory(
    connection_name, monkeypatch, tmp_path
):
    """Both were specified as delivering to the account's "root directory" -
    represented as "." (relative to the SFTP session's own start directory),
    confirmed with the user rather than guessed - see docs/decisions.md."""
    monkeypatch.setenv(f"SFTP_{connection_name}_HOST", "host")
    monkeypatch.setenv(f"SFTP_{connection_name}_USERNAME", "user")
    monkeypatch.setenv(
        f"SFTP_{connection_name}_PRIVATE_KEY", _fake_key_path(tmp_path)
    )
    monkeypatch.setenv(f"SFTP_{connection_name}_REMOTE_FOLDER", ".")

    assert SFTPConnectionService.get(connection_name).remote_folder == "."

```

env:

```env

# SFTP_EDL_HOST=TBD
# SFTP_EDL_PORT=22
# SFTP_EDL_USERNAME=TBD
# SFTP_EDL_PRIVATE_KEY=TBD
# SFTP_EDL_KNOWN_HOSTS=TBD
# SFTP_EDL_REMOTE_FOLDER=../../../landing1/gbm/b8fb/
# SFTP_EDL_MARKER_REMOTE_FOLDER=../../../landing1/gbm/b8fb/marker/

# SFTP_TENXCCD_HOST=TBD
# SFTP_TENXCCD_PORT=22
# SFTP_TENXCCD_USERNAME=TBD
# SFTP_TENXCCD_PRIVATE_KEY=TBD
# SFTP_TENXCCD_KNOWN_HOSTS=TBD
# SFTP_TENXCCD_REMOTE_FOLDER=/disk1/fenergoptp/

# SFTP_CCD_HOST=TBD
# SFTP_CCD_PORT=22
# SFTP_CCD_USERNAME=TBD
# SFTP_CCD_PRIVATE_KEY=TBD
# SFTP_CCD_KNOWN_HOSTS=TBD
# SFTP_CCD_REMOTE_FOLDER=/landing1/b8fb_fenergo/v8

# SFTP_DUCO_HOST=TBD
# SFTP_DUCO_PORT=TBD
# SFTP_DUCO_USERNAME=TBD
# SFTP_DUCO_PRIVATE_KEY=TBD
# SFTP_DUCO_KNOWN_HOSTS=TBD
# SFTP_DUCO_REMOTE_FOLDER=.


# SFTP_TMX_HOST=TBD
# SFTP_TMX_PORT=22
# SFTP_TMX_USERNAME=TBD
# SFTP_TMX_PRIVATE_KEY=TBD
# SFTP_TMX_KNOWN_HOSTS=TBD
# SFTP_TMX_REMOTE_FOLDER=.
```
