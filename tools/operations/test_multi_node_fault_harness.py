from __future__ import annotations

from types import SimpleNamespace
import socket
import threading
import time
import unittest

import multi_node_fault_harness as harness


CHAIN = "11" * 32
GENESIS = "22" * 32


class UdpEcho:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.1)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.socket.getsockname()[1])

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                payload, source = self.socket.recvfrom(65535)
                self.socket.sendto(payload, source)
            except socket.timeout:
                pass
            except OSError:
                return

    def close(self) -> None:
        self.stop.set()
        self.thread.join(timeout=2)
        self.socket.close()


class MultiNodeFaultHarnessTests(unittest.TestCase):
    def test_udp_relay_creates_and_heals_a_real_packet_partition(self) -> None:
        echo = UdpEcho()
        relay_port = harness.reserve_port(socket.SOCK_DGRAM)
        relay = harness.UdpRelay(relay_port, echo.port)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(0.3)
        try:
            client.sendto(b"before", ("127.0.0.1", relay_port))
            self.assertEqual(client.recvfrom(64)[0], b"before")
            relay.partition()
            client.sendto(b"during", ("127.0.0.1", relay_port))
            with self.assertRaises(socket.timeout):
                client.recvfrom(64)
            relay.heal()
            client.sendto(b"after", ("127.0.0.1", relay_port))
            self.assertEqual(client.recvfrom(64)[0], b"after")
        finally:
            client.close()
            relay.close()
            echo.close()

    def make_cluster(self) -> harness.ClusterHarness:
        cluster = object.__new__(harness.ClusterHarness)
        cluster.identity = None
        cluster.last_heads = {}
        cluster.last_finalized = {}
        return cluster

    @staticmethod
    def status(height: int, finalized: int = 0, chain: str = CHAIN) -> dict:
        return {
            "chain_id": chain,
            "genesis_hash": GENESIS,
            "unsafe_head": {"height": height},
            "finalized": {"epoch": finalized},
        }

    def test_cluster_validation_binds_identity_and_monotonic_heads(self) -> None:
        cluster = self.make_cluster()
        first = {"producer": self.status(10, 1), "observer-1": self.status(9, 1)}
        self.assertEqual(cluster.validate_cluster(first, 1), {"producer": 10, "observer-1": 9})
        second = {"producer": self.status(12, 2), "observer-1": self.status(12, 2)}
        cluster.validate_cluster(second, 1)
        with self.assertRaisesRegex(harness.HarnessError, "regressed"):
            cluster.validate_cluster({"producer": self.status(11, 2)}, 1)

    def test_cluster_validation_rejects_identity_divergence_and_excess_lag(self) -> None:
        cluster = self.make_cluster()
        with self.assertRaisesRegex(harness.HarnessError, "identity divergence"):
            cluster.validate_cluster({
                "producer": self.status(5),
                "observer-1": self.status(5, chain="99" * 32),
            }, 1)
        cluster = self.make_cluster()
        with self.assertRaisesRegex(harness.HarnessError, "lag exceeds"):
            cluster.validate_cluster({
                "producer": self.status(8),
                "observer-1": self.status(3),
            }, 2)

    def test_reserved_ports_are_bindable_for_tcp_and_udp(self) -> None:
        tcp = harness.reserve_port(socket.SOCK_STREAM)
        udp = harness.reserve_port(socket.SOCK_DGRAM)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
            tcp_socket.bind(("127.0.0.1", tcp))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            udp_socket.bind(("127.0.0.1", udp))


if __name__ == "__main__":
    unittest.main()
