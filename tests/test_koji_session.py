"""Tests for KojiClient retry and error handling."""

from __future__ import annotations

import ssl
import xmlrpc.client
from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from koji_sbom.koji_session import _BACKOFF_BASE, _MAX_RETRIES, KojiClient


@pytest.fixture()
def client() -> KojiClient:
    return KojiClient("https://brewhub.example.com/brewhub")


def _proxy_with_method(
    name: str, side_effect: object | None = None, return_value: object = None
) -> MagicMock:
    proxy = MagicMock()
    method = MagicMock()
    if side_effect is not None:
        method.side_effect = side_effect
    else:
        method.return_value = return_value
    setattr(proxy, name, method)
    return proxy


@contextmanager
def _koji_proxy(
    client: KojiClient,
    proxy: MagicMock,
    *,
    reconnect: MagicMock | None = None,
) -> Iterator[MagicMock]:
    """Install *proxy* and ensure reconnect after reset uses mocked ServerProxy."""
    if reconnect is not None:
        server_proxy = MagicMock(side_effect=[reconnect])
    else:
        server_proxy = MagicMock(return_value=proxy)
    with patch("koji_sbom.koji_session.xmlrpc.client.ServerProxy", server_proxy):
        client._local.proxy = proxy
        yield proxy


class TestCallWithRetry:
    def test_succeeds_first_try(self, client: KojiClient) -> None:
        proxy = _proxy_with_method("testMethod", return_value="ok")
        with _koji_proxy(client, proxy):
            assert client._call_with_retry("test", "testMethod", "arg1") == "ok"
        proxy.testMethod.assert_called_once_with("arg1")

    @patch("koji_sbom.koji_session.time.sleep")
    def test_retries_on_timeout_then_succeeds(
        self, mock_sleep: MagicMock, client: KojiClient
    ) -> None:
        proxy = _proxy_with_method("testMethod", side_effect=[TimeoutError("conn timed out"), "ok"])
        with _koji_proxy(client, proxy):
            assert client._call_with_retry("test", "testMethod") == "ok"
        assert proxy.testMethod.call_count == 2
        mock_sleep.assert_called_once_with(_BACKOFF_BASE)

    @patch("koji_sbom.koji_session.time.sleep")
    def test_retries_on_connection_error(self, mock_sleep: MagicMock, client: KojiClient) -> None:
        proxy = _proxy_with_method(
            "testMethod", side_effect=[ConnectionError("reset"), ConnectionError("reset"), "ok"]
        )
        with _koji_proxy(client, proxy):
            assert client._call_with_retry("test", "testMethod") == "ok"
        assert proxy.testMethod.call_count == 3
        assert mock_sleep.call_count == 2

    @patch("koji_sbom.koji_session.time.sleep")
    def test_retries_on_protocol_error(self, mock_sleep: MagicMock, client: KojiClient) -> None:
        err = xmlrpc.client.ProtocolError("url", 502, "Bad Gateway", {})
        proxy = _proxy_with_method("testMethod", side_effect=[err, "ok"])
        with _koji_proxy(client, proxy):
            assert client._call_with_retry("test", "testMethod") == "ok"
        assert proxy.testMethod.call_count == 2

    @patch("koji_sbom.koji_session.time.sleep")
    def test_retries_on_ssl_eof_error(self, mock_sleep: MagicMock, client: KojiClient) -> None:
        err = ssl.SSLEOFError("EOF occurred in violation of protocol")
        proxy = _proxy_with_method("testMethod", side_effect=[err, "ok"])
        with _koji_proxy(client, proxy):
            assert client._call_with_retry("test", "testMethod") == "ok"
        assert proxy.testMethod.call_count == 2
        mock_sleep.assert_called_once_with(_BACKOFF_BASE)

    @patch("koji_sbom.koji_session.time.sleep")
    def test_raises_after_max_retries(self, mock_sleep: MagicMock, client: KojiClient) -> None:
        proxy = _proxy_with_method("testMethod", side_effect=TimeoutError("persistent"))
        with _koji_proxy(client, proxy):
            with pytest.raises(TimeoutError, match="persistent"):
                client._call_with_retry("test", "testMethod")
        assert proxy.testMethod.call_count == _MAX_RETRIES + 1
        assert mock_sleep.call_count == _MAX_RETRIES

    @patch("koji_sbom.koji_session.time.sleep")
    def test_backoff_is_exponential(self, mock_sleep: MagicMock, client: KojiClient) -> None:
        proxy = _proxy_with_method(
            "testMethod", side_effect=[TimeoutError()] * _MAX_RETRIES + ["ok"]
        )
        with _koji_proxy(client, proxy):
            client._call_with_retry("test", "testMethod")
        waits = [call.args[0] for call in mock_sleep.call_args_list]
        expected = [_BACKOFF_BASE * (2**i) for i in range(_MAX_RETRIES)]
        assert waits == expected

    def test_fault_not_retried(self, client: KojiClient) -> None:
        proxy = _proxy_with_method(
            "testMethod", side_effect=xmlrpc.client.Fault(1, "no such build")
        )
        with _koji_proxy(client, proxy):
            with pytest.raises(xmlrpc.client.Fault):
                client._call_with_retry("test", "testMethod")
        proxy.testMethod.assert_called_once()

    @patch("koji_sbom.koji_session.time.sleep")
    def test_proxy_reset_on_retry(self, mock_sleep: MagicMock, client: KojiClient) -> None:
        old_proxy = MagicMock()
        old_proxy.testMethod.side_effect = TimeoutError()
        new_proxy = MagicMock()
        new_proxy.testMethod.return_value = "ok"
        with _koji_proxy(client, old_proxy, reconnect=new_proxy):
            result = client._call_with_retry("test", "testMethod")
        assert result == "ok"
        old_proxy.testMethod.assert_called_once()
        new_proxy.testMethod.assert_called_once()


class TestMulticallGetBuild:
    @patch("koji_sbom.koji_session.time.sleep")
    def test_multicall_retries_timeout_then_succeeds(
        self, mock_sleep: MagicMock, client: KojiClient
    ) -> None:
        build = {"build_id": 1, "nvr": "foo-1.0-1.el8"}
        proxy = MagicMock()
        proxy.multiCall.side_effect = [TimeoutError("conn timed out"), [[build]]]
        with _koji_proxy(client, proxy):
            result = client.multicall_get_build(["foo-1.0-1.el8"])
        assert len(result) == 1
        assert result[0]["build_id"] == 1
        assert proxy.multiCall.call_count == 2

    def test_multicall_falls_back_to_sequential_on_persistent_failure(
        self, client: KojiClient
    ) -> None:
        proxy = MagicMock()
        proxy.multiCall.side_effect = xmlrpc.client.Fault(1, "server error")
        build = {"build_id": 1, "nvr": "foo-1.0-1.el8"}
        proxy.getBuild.return_value = build
        with _koji_proxy(client, proxy):
            result = client.multicall_get_build(["foo-1.0-1.el8"])
        assert len(result) == 1
        assert result[0]["build_id"] == 1


class TestGracefulDegradation:
    @patch("koji_sbom.koji_session.time.sleep")
    def test_get_build_returns_none_after_exhausted_retries(
        self, mock_sleep: MagicMock, client: KojiClient
    ) -> None:
        proxy = MagicMock()
        proxy.getBuild.side_effect = TimeoutError("persistent")
        with _koji_proxy(client, proxy):
            assert client.get_build("foo-1.0-1.el8") is None

    @patch("koji_sbom.koji_session.time.sleep")
    def test_list_tagged_returns_empty_after_exhausted_retries(
        self, mock_sleep: MagicMock, client: KojiClient
    ) -> None:
        proxy = MagicMock()
        proxy.listTagged.side_effect = TimeoutError("persistent")
        with _koji_proxy(client, proxy):
            assert client.list_tagged("some-tag") == []

    @patch("koji_sbom.koji_session.time.sleep")
    def test_list_rpms_raises_after_exhausted_retries(
        self, mock_sleep: MagicMock, client: KojiClient
    ) -> None:
        proxy = MagicMock()
        proxy.listRPMs.side_effect = TimeoutError("persistent")
        with _koji_proxy(client, proxy):
            with pytest.raises(TimeoutError, match="persistent"):
                client.list_rpms(123)


class TestTransportSelection:
    def test_http_hub_uses_http_transport(self) -> None:
        client = KojiClient("http://koji.example/kojihub")
        with patch("koji_sbom.koji_session.xmlrpc.client.ServerProxy") as server_proxy:
            _ = client._proxy
        transport = server_proxy.call_args.kwargs["transport"]
        assert isinstance(transport, xmlrpc.client.Transport)
        assert not isinstance(transport, xmlrpc.client.SafeTransport)

    def test_https_hub_uses_safe_transport(self) -> None:
        client = KojiClient("https://koji.example/kojihub")
        with patch("koji_sbom.koji_session.xmlrpc.client.ServerProxy") as server_proxy:
            _ = client._proxy
        transport = server_proxy.call_args.kwargs["transport"]
        assert isinstance(transport, xmlrpc.client.SafeTransport)
