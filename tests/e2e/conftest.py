import os
import platform
import subprocess
import time
from pathlib import Path
from typing import Optional

import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.all import AsyncSniffer, Ether, conf, get_if_list  # noqa: E402


TAP_IFACE = "packet_tap0"
DEFAULT_DPDK_ARGS = "--no-huge --no-pci -l 0"
TX_DELAY_MS = "500"


def pytest_addoption(parser):
    parser.addoption(
        "--runtime",
        default=os.environ.get("FFG_RUNTIME") or os.environ.get("PACKET_TAP_RUNTIME"),
        help="Path to the ffg runtime binary.",
    )


@pytest.fixture(scope="session")
def runtime_binary(pytestconfig):
    runtime = pytestconfig.getoption("--runtime")
    if not runtime:
        pytest.skip("ffg runtime path was not provided")
    path = Path(runtime)
    if not path.exists():
        pytest.skip(f"ffg runtime does not exist: {path}")
    return path


@pytest.fixture(autouse=True)
def require_tap_host(runtime_binary):
    if platform.system() != "Linux":
        pytest.skip("DPDK tap e2e tests require Linux")
    if not Path("/dev/net/tun").exists():
        pytest.skip("/dev/net/tun is not available")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        pytest.skip("DPDK tap e2e tests require root or equivalent network capabilities")


@pytest.fixture
def packet_program(tmp_path):
    def write_program(packet: str, *, packet_count: Optional[int] = None) -> Path:
        lines = [f'DPDK_ARGS: "{DEFAULT_DPDK_ARGS}"']
        if packet_count is not None:
            lines.append(f"PACKET_COUNT: {packet_count}")
        lines.append(f"PACKET: {packet}")
        program = tmp_path / "traffic.packet"
        program.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return program

    return write_program


def reload_scapy_interfaces() -> None:
    reload = getattr(conf.ifaces, "reload", None)
    if reload is not None:
        reload()


def tap_is_visible() -> bool:
    reload_scapy_interfaces()
    return TAP_IFACE in get_if_list()


def permission_error(output: str) -> bool:
    markers = [
        "/dev/net/tun",
        "TUNSETIFF",
        "Operation not permitted",
        "Permission denied",
        "failed to create TAP",
    ]
    return any(marker in output for marker in markers)


@pytest.fixture
def capture_packets(runtime_binary):
    def run(program: Path, expected_count: int, *, timeout: float = 8.0):
        reload_scapy_interfaces()
        env = os.environ.copy()
        env["PACKET_RUNTIME_TX_DELAY_MS"] = TX_DELAY_MS
        process = subprocess.Popen(
            [str(runtime_binary), str(program)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and process.poll() is None:
            if tap_is_visible():
                break
            time.sleep(0.02)
        else:
            stdout, stderr = process.communicate(timeout=1)
            output = stdout + stderr
            if permission_error(output):
                pytest.skip(output.strip())
            pytest.fail(f"{TAP_IFACE} did not appear before runtime exited\n{output}")

        reload_scapy_interfaces()
        sniffer = AsyncSniffer(
            iface=TAP_IFACE,
            count=expected_count,
            timeout=max(1.0, timeout / 2),
            store=True,
        )
        sniffer.start()
        time.sleep(0.05)

        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            pytest.fail(f"runtime timed out\nstdout:\n{stdout}\nstderr:\n{stderr}")

        packets = list(sniffer.join())
        output = stdout + stderr
        if process.returncode != 0:
            if permission_error(output):
                pytest.skip(output.strip())
            pytest.fail(f"runtime failed with exit code {process.returncode}\n{output}")
        if len(packets) != expected_count:
            pytest.fail(
                f"captured {len(packets)} packet(s), expected {expected_count}\n"
                f"stdout:\n{stdout}\nstderr:\n{stderr}"
            )
        return [Ether(bytes(packet)) for packet in packets]

    return run
