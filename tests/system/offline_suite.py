"""Opt-in pytest plugin: real Python sockets may contact loopback only.

Tests may replace transport/DNS with pure doubles. Attempted real external
effects are retained and asserted even if application code swallows the error.
Live/existing-target opt-ins must remain off for this checkpoint.
"""
import ipaddress
import socket

import pytest


@pytest.fixture(autouse=True)
def loopback_suite_boundary():
    patcher = pytest.MonkeyPatch()
    violations = []
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_dns = socket.getaddrinfo

    def check(address):
        if isinstance(address, str):
            return  # Unix IPC is used by isolated local workers.
        try:
            if ipaddress.ip_address(address[0]).is_loopback:
                return
        except ValueError:
            pass
        violations.append("external socket")
        raise AssertionError("offline suite: only loopback real sockets are allowed")

    def connect(sock, address):
        check(address)
        return original_connect(sock, address)
    def connect_ex(sock, address):
        check(address)
        return original_connect_ex(sock, address)
    def dns(host, *args, **kwargs):
        decoded = host.decode() if isinstance(host, bytes) else host
        if decoded not in {None, "localhost", "", "0.0.0.0", "::"}:
            check((decoded, 0))
        return original_dns(host, *args, **kwargs)
    patcher.setattr(socket.socket, "connect", connect)
    patcher.setattr(socket.socket, "connect_ex", connect_ex)
    patcher.setattr(socket, "getaddrinfo", dns)
    try:
        yield
        assert not violations, "a real external effect was attempted and may have been swallowed"
    finally:
        patcher.undo()
