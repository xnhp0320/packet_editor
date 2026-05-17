from collections import Counter
import re

import pytest
from scapy.all import ICMP, IP, TCP, UDP
from scapy.layers.vxlan import VXLAN


ETHER = 'Ether(dst="ff:ff:ff:ff:ff:ff",src="02:64:74:61:70:00")'
WORKER_RE = re.compile(r"PMD worker (\d+) lcore (\d+) queue (\d+) sent (\d+)/(\d+) packet\(s\)")


@pytest.mark.parametrize(
    ("packet", "layer", "checks"),
    [
        (
            f'{ETHER}/IP(src="192.0.2.1",dst="192.0.2.2")/TCP(sport=1234,dport=80,flags=2)',
            TCP,
            {"sport": 1234, "dport": 80},
        ),
        (
            f'{ETHER}/IP(src="192.0.2.3",dst="192.0.2.4")/UDP(sport=1235,dport=53)',
            UDP,
            {"sport": 1235, "dport": 53},
        ),
        (
            f'{ETHER}/IP(src="192.0.2.5",dst="192.0.2.6")/ICMP(type=8,code=0,id=7,seq=9)',
            ICMP,
            {"type": 8, "code": 0, "id": 7, "seq": 9},
        ),
    ],
)
def test_generates_normal_ipv4_l4_packets(packet_program, capture_packets, packet, layer, checks):
    packets = capture_packets(packet_program(packet, packet_count=1), 1)

    assert IP in packets[0]
    assert layer in packets[0]
    for field, value in checks.items():
        assert getattr(packets[0][layer], field) == value


def test_generates_ipv4_and_tcp_options(packet_program, capture_packets):
    program = packet_program(
        f'{ETHER}/IP(src="198.51.100.1",dst="198.51.100.2",'
        'options=IPOption_NOP()/IPOption_EOL())/'
        'TCP(sport=1234,dport=443,flags=2,options=TCPOption_MSS(value=1460))',
        packet_count=1,
    )

    packet = capture_packets(program, 1)[0]

    assert packet[IP].ihl == 6
    assert packet[TCP].dataofs == 6
    assert ("MSS", 1460) in packet[TCP].options


@pytest.mark.parametrize(
    ("inner_l4", "layer", "checks"),
    [
        ('TCP(sport=2000,dport=2001,flags=2)', TCP, {"sport": 2000, "dport": 2001}),
        ('UDP(sport=3000,dport=3001)', UDP, {"sport": 3000, "dport": 3001}),
        ('ICMP(type=8,code=0,id=10,seq=11)', ICMP, {"type": 8, "code": 0, "id": 10, "seq": 11}),
    ],
)
def test_generates_vxlan_encapsulated_ipv4_packets(packet_program, capture_packets, inner_l4, layer, checks):
    program = packet_program(
        f'{ETHER}/IP(src="203.0.113.1",dst="203.0.113.2")/UDP()/VXLAN(vni=42)/'
        f'Ether(dst="02:00:00:00:00:02",src="02:00:00:00:00:01")/'
        f'IP(src="10.10.0.1",dst="10.10.0.2")/{inner_l4}',
        packet_count=1,
    )

    packet = capture_packets(program, 1)[0]
    inner = packet[VXLAN].payload

    assert VXLAN in packet
    assert packet[VXLAN].vni == 42
    assert IP in inner
    assert layer in inner
    for field, value in checks.items():
        assert getattr(inner[layer], field) == value


def test_generates_cartesian_ipv4_and_tcp_port_ranges(packet_program, capture_packets):
    program = packet_program(
        f'{ETHER}/IP(src="[10.0.0.1-10.0.0.4]",dst="10.0.1.1")/'
        'TCP(sport="[10000-10002]",dport=443,flags=2)',
        packet_count=12,
    )

    packets = capture_packets(program, 12)
    flows = {(packet[IP].src, packet[TCP].sport) for packet in packets}

    assert flows == {
        (ip, port)
        for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
        for port in [10000, 10001, 10002]
    }


def test_multi_pmd_workers_emit_duplicate_cartesian_ranges(packet_program, capture_packets):
    program = packet_program(
        f'{ETHER}/IP(src="[10.0.0.1-10.0.0.2]",dst="10.0.1.1")/'
        'TCP(sport="[10000-10001]",dport=443,flags=2)',
        packet_count=4,
        dpdk_args="--no-huge --no-pci -l 0-2",
        pmd_threads=2,
        tx_batch_size=4,
    )

    result = capture_packets(program, 8, with_output=True)
    flows = Counter((packet[IP].src, packet[TCP].sport) for packet in result.packets)
    expected_flows = {
        (ip, port)
        for ip in ["10.0.0.1", "10.0.0.2"]
        for port in [10000, 10001]
    }

    assert set(flows) == expected_flows
    assert all(count == 2 for count in flows.values())
    assert "pmd_threads 2" in result.stdout
    assert "tx_batch_size 4" in result.stdout

    workers = [
        {
            "worker": int(match.group(1)),
            "lcore": int(match.group(2)),
            "queue": int(match.group(3)),
            "sent": int(match.group(4)),
            "attempted": int(match.group(5)),
        }
        for match in WORKER_RE.finditer(result.stdout)
    ]
    assert len(workers) == 2
    assert {worker["worker"] for worker in workers} == {0, 1}
    assert {worker["queue"] for worker in workers} == {0, 1}
    assert all(worker["sent"] == 4 and worker["attempted"] == 4 for worker in workers)
