import pytest

from vant.modules.inventory.collector import (
    safe_json_command,
    safe_text_command,
    detect_os_type,
    _parse_install_date,
)


class TestSafeJsonCommand:
    def test_returns_empty_list_on_error(self):
        assert safe_json_command("invalid_command_xyz") == []

    def test_returns_list_from_json_array(self, mocker):
        mocker.patch("subprocess.check_output", return_value='[{"name": "test"}]')
        result = safe_json_command("some command")
        assert result == [{"name": "test"}]

    def test_wraps_dict_in_list(self, mocker):
        mocker.patch("subprocess.check_output", return_value='{"name": "test"}')
        result = safe_json_command("some command")
        assert result == [{"name": "test"}]

    def test_handles_non_json_output(self, mocker):
        mocker.patch("subprocess.check_output", return_value="not json")
        assert safe_json_command("some command") == []

    def test_handles_empty_output(self, mocker):
        mocker.patch("subprocess.check_output", return_value="")
        assert safe_json_command("some command") == []


class TestSafeTextCommand:
    def test_returns_output(self, mocker):
        mocker.patch("subprocess.check_output", return_value="output text")
        assert safe_text_command("some command") == "output text"

    def test_returns_empty_on_error(self):
        assert safe_text_command("invalid_command_xyz") == ""


class TestDetectOsType:
    def test_windows_11_by_build(self, mocker):
        mocker.patch("platform.system", return_value="Windows")
        mocker.patch("platform.version", return_value="10.0.22621")
        assert detect_os_type() == "windows_11"

    def test_windows_10(self, mocker):
        mocker.patch("platform.system", return_value="Windows")
        mocker.patch("platform.version", return_value="10.0.19045")
        mocker.patch("platform.release", return_value="10")
        assert detect_os_type() == "windows_10"

    def test_windows_server_2022(self, mocker):
        mocker.patch("platform.system", return_value="Windows")
        mocker.patch("platform.version", return_value="10.0.20348")
        mocker.patch("platform.release", return_value="10")
        mocker.patch("platform.win32_ver", return_value=("", "", "Windows Server 2022 Standard", ""))
        assert detect_os_type() == "windows_server_2022"

    def test_non_windows(self, mocker):
        mocker.patch("platform.system", return_value="Linux")
        assert detect_os_type() == "other"


class TestParseInstallDate:
    def test_valid_date(self):
        assert _parse_install_date("20240115") == "2024-01-15"

    def test_none_input(self):
        assert _parse_install_date(None) is None

    def test_empty_string(self):
        assert _parse_install_date("") is None

    def test_already_formatted(self):
        assert _parse_install_date("2024-01-15") == "2024-01-15"
