import socket

import pytest

from agentguard.config import Settings
from agentguard.eval.suites import load_scenarios
from agentguard.policy import load_policy


class NetworkBlocked(RuntimeError):
    pass


LOOPBACK = {"127.0.0.1", "::1", "localhost"}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Every test runs offline: any non-loopback connection attempt fails loudly.

    Loopback is allowed because asyncio on Windows builds its self-pipe from a local
    socket pair (used by Streamlit's AppTest).
    """
    real_connect, real_connect_ex = socket.socket.connect, socket.socket.connect_ex

    def _check(address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in LOOPBACK:
            raise NetworkBlocked(f"tests must not open network connections (attempted {address!r})")

    def connect(self, address):
        _check(address)
        return real_connect(self, address)

    def connect_ex(self, address):
        _check(address)
        return real_connect_ex(self, address)

    def create_connection(address, *args, **kwargs):
        _check(address)
        raise NetworkBlocked("create_connection is not used by the sandbox")

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "create_connection", create_connection)


@pytest.fixture
def policy():
    return load_policy()


@pytest.fixture
def scenarios():
    return load_scenarios()


@pytest.fixture
def settings(tmp_path):
    return Settings(runs_dir=tmp_path / "runs", cache_dir=tmp_path / "cache", llm_mode="off")
