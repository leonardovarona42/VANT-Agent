import logging
import socket

import pytest

from vant.utils import (
    detect_host,
    detect_os,
    sleep_with_stop,
    get_mac_address,
    get_current_ips,
    configure_logging,
)


class TestDetectHost:
    def test_returns_hostname(self, mocker):
        mocker.patch("socket.gethostname", return_value="my-pc")
        mocker.patch("socket.gethostbyname", return_value="192.168.1.10")
        host, ip = detect_host()
        assert host == "my-pc"
        assert ip == "192.168.1.10"

    def test_fallback_to_udp_when_localhost(self, mocker):
        mocker.patch("socket.gethostname", return_value="my-pc")
        mocker.patch("socket.gethostbyname", return_value="127.0.0.1")
        fake_sock = mocker.MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.getsockname.return_value = ("10.0.0.5", 12345)
        mocker.patch("socket.socket", return_value=fake_sock)
        host, ip = detect_host()
        assert ip == "10.0.0.5"

    def test_returns_empty_ip_on_failure(self, mocker):
        mocker.patch("socket.gethostname", return_value="my-pc")
        mocker.patch("socket.gethostbyname", side_effect=Exception("no network"))
        mocker.patch("socket.socket", side_effect=Exception("no socket"))
        host, ip = detect_host()
        assert ip == ""


class TestDetectOs:
    def test_detect_windows_10(self, mocker):
        mocker.patch("platform.system", return_value="Windows")
        mocker.patch("platform.version", return_value="10.0.19045")
        mocker.patch("platform.release", return_value="10")
        result = detect_os()
        assert result == "windows_10"

    def test_detect_windows_11(self, mocker):
        mocker.patch("platform.system", return_value="Windows")
        mocker.patch("platform.version", return_value="10.0.22621")
        result = detect_os()
        assert result == "windows_11"

    def test_detect_windows_server_2022(self, mocker):
        mocker.patch("platform.system", return_value="Windows")
        mocker.patch("platform.version", return_value="10.0.20348")
        mocker.patch("platform.release", return_value="10")
        mocker.patch("platform.win32_ver", return_value=("", "", "Server 2022", ""))
        result = detect_os()
        assert result == "windows_server_2022"

    def test_detect_ubuntu(self, mocker):
        mocker.patch("platform.system", return_value="Linux")
        mocker.patch("builtins.open", mocker.mock_open(read_data='NAME="Ubuntu"\nVERSION_ID="24.04"\n'))
        result = detect_os()
        assert result == "ubuntu_24_04"

    def test_detect_macos(self, mocker):
        mocker.patch("platform.system", return_value="Darwin")
        result = detect_os()
        assert result == "macos_15"

    def test_detect_other(self, mocker):
        mocker.patch("platform.system", return_value="UnknownOS")
        result = detect_os()
        assert result == "other"


class TestSleepWithStop:
    def test_returns_when_stop_is_set(self, mock_stop_event, mocker):
        mock_sleep = mocker.patch("time.sleep")
        mock_stop_event._stopped = True
        sleep_with_stop(mock_stop_event, 10)
        mock_sleep.assert_not_called()

    def test_sleeps_full_duration_when_no_stop(self, mock_stop_event, mocker):
        mock_sleep = mocker.patch("time.sleep")
        sleep_with_stop(mock_stop_event, 3)
        assert mock_sleep.call_count == 3

    def test_interrupts_midway(self, mock_stop_event, mocker):
        mock_sleep = mocker.patch("time.sleep")

        def trigger_stop(*args, **kwargs):
            if mock_sleep.call_count >= 2:
                mock_stop_event._stopped = True

        mock_sleep.side_effect = trigger_stop
        sleep_with_stop(mock_stop_event, 10)
        # 2 sleeps complete, 3rd iteration detects stop before sleep
        assert mock_sleep.call_count == 2


class TestGetCurrentIps:
    def test_returns_non_local_ips(self, mocker):
        mocker.patch("socket.gethostname", return_value="pc")
        mocker.patch("socket.gethostbyname", return_value="192.168.1.10")
        ips = get_current_ips()
        assert "192.168.1.10" in ips

    def test_excludes_127_dot(self, mocker):
        mocker.patch("socket.gethostname", return_value="pc")
        mocker.patch("socket.gethostbyname", return_value="127.0.0.1")
        fake_sock = mocker.MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.getsockname.return_value = ("10.0.0.5", 12345)
        mocker.patch("socket.socket", return_value=fake_sock)
        ips = get_current_ips()
        assert "127.0.0.1" not in ips
        assert "10.0.0.5" in ips


class TestConfigureLogging:
    def test_creates_logger(self, tmp_path):
        cfg = {"level": "INFO", "file": str(tmp_path / "test.log")}
        logger = configure_logging(cfg, str(tmp_path / "config.yaml"))
        assert logger.name == "vant-agent"
        assert logger.level == logging.INFO

    def test_logger_has_file_handler(self, tmp_path):
        log_file = tmp_path / "agent.log"
        cfg = {"level": "DEBUG", "file": str(log_file)}
        logger = configure_logging(cfg, str(tmp_path / "config.yaml"))
        handlers = logger.handlers
        assert any(isinstance(h, logging.handlers.RotatingFileHandler) for h in handlers)

    def test_logger_has_stream_handler(self, tmp_path):
        cfg = {"level": "DEBUG", "file": str(tmp_path / "test.log")}
        logger = configure_logging(cfg, str(tmp_path / "config.yaml"))
        assert any(isinstance(h, logging.StreamHandler) for h in logger.handlers)


class TestGetMacAddress:
    def test_windows_powershell_fallback(self, mocker):
        mocker.patch("platform.system", return_value="Windows")
        mocker.patch("subprocess.check_output", return_value="AA:BB:CC:DD:EE:FF")
        mac = get_mac_address()
        assert mac == "AA:BB:CC:DD:EE:FF"

    def test_windows_uuid_fallback(self, mocker):
        mocker.patch("platform.system", return_value="Windows")
        mocker.patch("subprocess.check_output", side_effect=Exception("no powershell"))
        mocker.patch("uuid.getnode", return_value=0x112233445566)
        mac = get_mac_address()
        # 0x112233445566 formatted as MAC
        assert ":" in mac
        assert len(mac) == 17

    def test_linux(self, mocker):
        mocker.patch("platform.system", return_value="Linux")
        mocker.patch("builtins.open", mocker.mock_open(read_data="aa:bb:cc:dd:ee:ff\n"))
        mac = get_mac_address()
        assert mac == "AA:BB:CC:DD:EE:FF"

    def test_returns_empty_on_error(self, mocker):
        mocker.patch("platform.system", return_value="UnknownOS")
        mac = get_mac_address()
        assert mac == ""
