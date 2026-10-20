import pytest

from vant.api import VantClient


@pytest.fixture
def client(sample_config_dict):
    return VantClient(sample_config_dict)


class TestVantClientInit:
    def test_urls_from_config(self, client):
        assert client.base_url == "http://localhost:8000"
        assert client.logs_url == "http://localhost:9201"

    def default_auth_is_none(self, client):
        assert client.auth_mode == "none"
        assert client.token == ""

    def test_timeout_from_config(self, client):
        assert client.timeout == 15


class TestVantClientAuth:
    def test_token_auth_header(self, sample_config_dict):
        sample_config_dict["server"]["auth_mode"] = "token"
        sample_config_dict["server"]["auth_token"] = "my-token"
        c = VantClient(sample_config_dict)
        headers = c._headers()
        assert headers["Authorization"] == "Bearer my-token"

    def test_basic_auth(self, sample_config_dict):
        sample_config_dict["server"]["auth_mode"] = "basic"
        sample_config_dict["server"]["auth_username"] = "user"
        sample_config_dict["server"]["auth_password"] = "pass"
        c = VantClient(sample_config_dict)
        auth = c._auth()
        assert auth == ("user", "pass")

    def test_no_auth(self, client):
        assert "Authorization" not in client._headers()
        assert client._auth() is None


class TestVantClientUrls:
    def test_ingest_logs_empty_batch(self, client):
        result = client.ingest_logs([])
        assert result == {"ok": True, "inserted": 0}

    def test_upsert_source_includes_source_field(self, client, mocker):
        mock_post = mocker.patch.object(client, "_post")
        client.upsert_source({"source_id": "test", "source_type": "file_log"})
        mock_post.assert_called_once()
        url, payload = mock_post.call_args[0]
        assert "/logs/api/sources/" in url
        assert payload["source_id"] == "test"

    def test_send_heartbeat_without_ip(self, client, mocker):
        mock_post = mocker.patch.object(client, "_post")
        client.send_heartbeat("agent-1")
        _, payload = mock_post.call_args[0]
        assert payload["agent_id"] == "agent-1"
        assert "ip_address" not in payload

    def test_send_heartbeat_with_ip(self, client, mocker):
        mock_post = mocker.patch.object(client, "_post")
        client.send_heartbeat("agent-1", ip_address="10.0.0.1")
        _, payload = mock_post.call_args[0]
        assert payload["ip_address"] == "10.0.0.1"

    def test_submit_inventory_payload(self, client, mocker):
        mock_post = mocker.patch.object(client, "_post")
        hw = {"cpu_model": "Intel"}
        sw = [{"name": "App1"}]
        client.submit_inventory("agent-1", hw, sw)
        _, payload = mock_post.call_args[0]
        assert payload["agent_id"] == "agent-1"
        assert payload["hardware"] == hw
        assert payload["software"] == sw

    def test_send_command_result(self, client, mocker):
        mock_post = mocker.patch.object(client, "_post")
        client.send_command_result("cmd-1", "completed", {"key": "val"}, "no error")
        _, payload = mock_post.call_args[0]
        assert payload["command_id"] == "cmd-1"
        assert payload["status"] == "completed"

    def test_ingest_logs_sends_post(self, client, mocker):
        mock_post = mocker.patch.object(client, "_post")
        mock_post.return_value.json.return_value = {"ok": True, "inserted": 3}
        events = [{"event": "test"}]
        result = client.ingest_logs(events)
        mock_post.assert_called_once()
        _, payload = mock_post.call_args[0]
        assert payload["events"] == events
        assert result == {"ok": True, "inserted": 3}


class TestVantClientTls:
    def test_tls_verify_default_true(self, sample_config_dict):
        c = VantClient(sample_config_dict)
        assert c.verify is True

    def test_tls_ca_cert(self, sample_config_dict, tmp_path):
        ca = tmp_path / "ca.pem"
        ca.write_text("fake cert", encoding="utf-8")
        sample_config_dict["server"]["tls"] = {"verify": True, "ca_cert": str(ca)}
        c = VantClient(sample_config_dict)
        assert c.verify == str(ca)

    def test_tls_ca_cert_missing(self, sample_config_dict):
        sample_config_dict["server"]["tls"] = {"verify": True, "ca_cert": "/nonexistent/ca.pem"}
        c = VantClient(sample_config_dict)
        assert c.verify is True
