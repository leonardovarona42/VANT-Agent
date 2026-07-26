import pytest

from vant.modules.heartbeat.service import HeartbeatService


@pytest.fixture
def hb_service(sample_config_dict):
    return HeartbeatService(sample_config_dict, None)


class TestHeartbeatServiceInit:
    def test_interval_from_config(self, hb_service):
        assert hb_service.interval == 300


class TestProcessCommands:
    def test_push_config_applies_and_reloads(self, hb_service, mocker):
        mock_inv = mocker.MagicMock()
        mock_client = mocker.MagicMock()
        mock_logger = mocker.MagicMock()
        mock_apply = mocker.patch.object(hb_service, "_apply_config")
        mock_save = mocker.patch("vant.config.save_config")

        heartbeat_data = {
            "commands": [{
                "command_id": "cmd-1",
                "command_type": "push_config",
                "payload": {"config": {"agent": {"check_interval": 120}}},
            }]
        }
        result = hb_service.process_commands(heartbeat_data, mock_inv, mock_client, mock_logger, "/path/config.yaml", mock_logger)
        assert result == "reload"
        mock_apply.assert_called_once()
        mock_client.send_command_result.assert_called_once_with("cmd-1", "completed", {"status": "applied"})

    def test_update_inventory(self, hb_service, mocker):
        mock_inv = mocker.MagicMock()
        mock_client = mocker.MagicMock()
        mock_logger = mocker.MagicMock()

        heartbeat_data = {
            "commands": [{
                "command_id": "cmd-2",
                "command_type": "update_inventory",
                "payload": {},
            }]
        }
        result = hb_service.process_commands(heartbeat_data, mock_inv, mock_client, mock_logger, "/path", mock_logger)
        mock_inv.collect_and_submit.assert_called_once()
        mock_client.send_command_result.assert_called_once_with("cmd-2", "completed", {"status": "ok"})
        assert result is None

    def test_restart_agent_raises_systemexit(self, hb_service, mocker):
        mock_inv = mocker.MagicMock()
        mock_client = mocker.MagicMock()
        mock_logger = mocker.MagicMock()

        heartbeat_data = {
            "commands": [{
                "command_id": "cmd-3",
                "command_type": "restart_agent",
                "payload": {},
            }]
        }
        with pytest.raises(SystemExit, match="Restart requested by server"):
            hb_service.process_commands(heartbeat_data, mock_inv, mock_client, mock_logger, "/path", mock_logger)

    def test_stop_agent_returns_stop(self, hb_service, mocker):
        mock_inv = mocker.MagicMock()
        mock_client = mocker.MagicMock()
        mock_logger = mocker.MagicMock()

        heartbeat_data = {
            "commands": [{
                "command_id": "cmd-4",
                "command_type": "stop_agent",
                "payload": {},
            }]
        }
        result = hb_service.process_commands(heartbeat_data, mock_inv, mock_client, mock_logger, "/path", mock_logger)
        assert result == "stop"

    def test_unknown_command(self, hb_service, mocker):
        mock_inv = mocker.MagicMock()
        mock_client = mocker.MagicMock()
        mock_logger = mocker.MagicMock()

        heartbeat_data = {
            "commands": [{
                "command_id": "cmd-5",
                "command_type": "unknown_type",
                "payload": {},
            }]
        }
        result = hb_service.process_commands(heartbeat_data, mock_inv, mock_client, mock_logger, "/path", mock_logger)
        mock_client.send_command_result.assert_called_once()
        args = mock_client.send_command_result.call_args[0]
        assert args[2]["status"] == "unknown_command:unknown_type"
        assert result is None

    def test_multiple_commands(self, hb_service, mocker):
        mock_inv = mocker.MagicMock()
        mock_client = mocker.MagicMock()
        mock_logger = mocker.MagicMock()

        heartbeat_data = {
            "commands": [
                {"command_id": "c1", "command_type": "update_inventory", "payload": {}},
                {"command_id": "c2", "command_type": "push_config", "payload": {"config": {"agent": {}}}},
            ]
        }
        mocker.patch.object(hb_service, "_apply_config")
        result = hb_service.process_commands(heartbeat_data, mock_inv, mock_client, mock_logger, "/path", mock_logger)
        # push_config triggers reload, so result should be "reload"
        assert result == "reload"

    def test_no_commands(self, hb_service, mocker):
        result = hb_service.process_commands({}, None, None, None, None, None)
        assert result is None


class TestApplyConfig:
    def test_applies_sections(self, hb_service, mocker, tmp_path):
        mock_save = mocker.patch("vant.config.save_config")
        config_path = str(tmp_path / "config.yaml")

        hb_service._apply_config({"inventory": {"enabled": False}, "agent": {"check_interval": 30}}, config_path, mocker.MagicMock())
        mock_save.assert_called_once()
        args = mock_save.call_args[0]
        assert args[0] == config_path
        assert args[1]["inventory"]["enabled"] is False
        assert args[1]["agent"]["check_interval"] == 30

    def test_ignores_unknown_sections(self, hb_service, mocker, tmp_path):
        mock_save = mocker.patch("vant.config.save_config")
        config_path = str(tmp_path / "config.yaml")

        hb_service._apply_config({"unknown_section": {"key": "val"}}, config_path, mocker.MagicMock())
        # save_config should NOT be called if no known sections
        # Actually the code only saves if updates is non-empty, and unknown_section is not in the whitelist
        # So updates will be empty
        mock_save.assert_not_called()
