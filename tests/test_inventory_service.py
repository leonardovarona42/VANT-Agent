import pytest

from vant.modules.inventory.service import InventoryService


@pytest.fixture
def inv_service(sample_config_dict, tmp_path):
    sample_config_dict["_config_path"] = str(tmp_path / "config.yaml")
    return InventoryService(sample_config_dict)


class TestInventoryServiceInit:
    def test_no_agent_id_on_init(self, inv_service):
        assert inv_service.agent_id is None

    def test_state_dir_created(self, inv_service, tmp_path):
        state_dir = tmp_path / ".vant_state"
        assert state_dir.exists()

    def test_config_version_defaults_to_zero(self, inv_service):
        assert inv_service.config_version == 0


class TestInventoryServiceState:
    def test_save_and_load_state(self, inv_service):
        inv_service.config_version = 5
        assert inv_service.config_version == 5

        # Create new instance to verify persistence
        inv_service2 = InventoryService(inv_service.config)
        assert inv_service2.config_version == 5

    def test_state_dir_created(self, inv_service):
        assert inv_service._state_dir.exists()


class TestInventoryServiceRegister:
    def test_register_success(self, inv_service, mocker, mock_response):
        mock_resp = mock_response(status_code=201, json_data={"agent_id": "new-id-123", "created": True})
        mock_client = mocker.MagicMock()
        mock_client.register_agent.return_value = mock_resp

        mocker.patch("vant.modules.inventory.service.detect_host", return_value=("host1", "10.0.0.1"))
        mocker.patch("vant.modules.inventory.service.detect_os", return_value="windows_11")
        mocker.patch("vant.modules.inventory.service.get_mac_address", return_value="AA:BB:CC:DD:EE:FF")
        mocker.patch("vant.modules.inventory.service.platform.node", return_value="host1")
        mocker.patch("vant.modules.inventory.service.platform.version", return_value="10.0.22621")
        mocker.patch("vant.modules.inventory.service.platform.machine", return_value="AMD64")

        result = inv_service.register(mock_client, mocker.MagicMock())
        assert result is True
        assert inv_service.agent_id == "new-id-123"

    def test_register_failure_returns_false(self, inv_service, mocker):
        mock_client = mocker.MagicMock()
        mock_client.register_agent.side_effect = Exception("connection error")
        result = inv_service.register(mock_client, mocker.MagicMock())
        assert result is False
        assert inv_service.agent_id is None

    def test_register_non_200(self, inv_service, mocker, mock_response):
        mock_resp = mock_response(status_code=500)
        mock_client = mocker.MagicMock()
        mock_client.register_agent.return_value = mock_resp
        result = inv_service.register(mock_client, mocker.MagicMock())
        # Should return False when status is not 200/201
        assert result is False


class TestInventoryServiceHeartbeat:
    def test_heartbeat_no_agent_id(self, inv_service, mocker):
        mock_client = mocker.MagicMock()
        assert inv_service.agent_id is None

        result = inv_service.heartbeat(mock_client, mocker.MagicMock())
        assert result is None
        mock_client.send_heartbeat.assert_not_called()

    def test_heartbeat_returns_commands(self, inv_service, mocker, mock_response):
        inv_service.agent_id = "test-id"
        mock_client = mocker.MagicMock()
        mock_resp = mock_response(status_code=200, json_data={"commands": [{"command_id": "c1", "command_type": "update_inventory"}]})
        mock_client.send_heartbeat.return_value = mock_resp

        data = inv_service.heartbeat(mock_client, mocker.MagicMock())
        assert data["commands"][0]["command_id"] == "c1"

    def test_heartbeat_returns_none_on_error(self, inv_service, mocker):
        inv_service.agent_id = "test-id"
        mock_client = mocker.MagicMock()
        mock_client.send_heartbeat.side_effect = Exception("timeout")

        data = inv_service.heartbeat(mock_client, mocker.MagicMock())
        assert data is None


class TestInventoryServiceCollectAndSubmit:
    def test_no_agent_id_returns_false(self, inv_service, mocker):
        mock_client = mocker.MagicMock()
        result = inv_service.collect_and_submit(mock_client, mocker.MagicMock())
        assert result is False

    def test_submit_windows_success(self, inv_service, mocker, mock_response):
        inv_service.agent_id = "test-id"
        mock_client = mocker.MagicMock()
        mock_client.submit_inventory.return_value = mock_response(status_code=200, json_data={"software_count": 10})

        mocker.patch("os.name", "nt")
        mocker.patch("vant.modules.inventory.service.collect_windows_hardware", return_value={"cpu_model": "Intel i7"})
        mocker.patch("vant.modules.inventory.service.collect_windows_software", return_value=[{"name": "App1"}])

        result = inv_service.collect_and_submit(mock_client, mocker.MagicMock())
        assert result is True

    def test_submit_linux_stub(self, inv_service, mocker, mock_response):
        inv_service.agent_id = "test-id"
        mock_client = mocker.MagicMock()
        mock_client.submit_inventory.return_value = mock_response(status_code=200, json_data={"software_count": 0})

        mocker.patch("os.name", "posix")
        result = inv_service.collect_and_submit(mock_client, mocker.MagicMock())
        assert result is True


class TestInventoryServiceShouldSubmit:
    def test_should_submit_when_no_last(self, inv_service):
        assert inv_service.should_submit(300) is True

    def test_should_not_submit_recent(self, inv_service):
        import time
        inv_service._state["last_inventory"] = time.time()
        assert inv_service.should_submit(300) is False

    def test_should_submit_after_interval(self, inv_service):
        import time
        inv_service._state["last_inventory"] = time.time() - 600
        assert inv_service.should_submit(300) is True


class TestInventoryServiceHash:
    def test_hash_hw(self, inv_service):
        hw = {"serial_number": "SN123", "cpu_model": "Intel", "ram_total_gb": 16}
        h = inv_service._hash_hw(hw)
        assert isinstance(h, int)
        # Same input should produce same hash
        assert inv_service._hash_hw(hw) == h

    def test_hash_hw_different(self, inv_service):
        h1 = inv_service._hash_hw({"serial_number": "A", "cpu_model": "Intel", "ram_total_gb": 16})
        h2 = inv_service._hash_hw({"serial_number": "B", "cpu_model": "Intel", "ram_total_gb": 16})
        assert h1 != h2
