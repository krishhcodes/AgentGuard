import socket

import pytest

from tests.conftest import NetworkBlocked


def test_external_connections_are_blocked():
    s = socket.socket()
    try:
        with pytest.raises(NetworkBlocked):
            s.connect(("93.184.215.14", 80))
    finally:
        s.close()
    with pytest.raises(NetworkBlocked):
        socket.create_connection(("api.groq.com", 443))
