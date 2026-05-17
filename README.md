# FlowForge

FlowForge is a DPDK-native traffic generator driven by a compact, Scapy-like
packet description language. It is built for generating high-rate packet streams
from readable packet programs, including range expressions that expand one packet
template into a set of flows.

The command-line binary is `ffg`.

## Features

- Scapy-like packet construction syntax:

  ```text
  Ether()/IP(src="192.168.0.1",dst="192.168.0.2")/UDP(sport=1234,dport=5678)
  ```

- Flow ranges for traffic generation:

  ```text
  IP(src="[10.0.0.1-10.0.0.4]")/TCP(sport="[10000-10002]",dport=443)
  ```

  The runtime expands packet field ranges as a Cartesian product and transmits
  each planned flow once unless `PACKET_COUNT` caps the run.

- DPDK-native runtime path for high-performance packet generation.
- Protocol support for Ethernet, VLAN, IPv4, IPv6, TCP, UDP, ICMP, VXLAN,
  payload sizing, IPv4 options, and TCP options.
- Packet validation and serialization are separated from the DPDK runtime, so
  most parser/checker/serializer behavior is covered by fast unit tests.
- Optional pytest + Scapy end-to-end tests validate real packets emitted through
  the DPDK tap runtime.

## Packet Programs

A runtime program is a small text file with variables:

```text
DPDK_ARGS: "--no-huge --no-pci -l 0"
PACKET_COUNT: 12
PACKET: Ether(dst="ff:ff:ff:ff:ff:ff",src="02:64:74:61:70:00")/IP(src="[10.0.0.1-10.0.0.4]",dst="10.0.1.1")/TCP(sport="[10000-10002]",dport=443)
```

Supported runtime variables:

- `DPDK_ARGS`: string passed to DPDK EAL initialization.
- `PACKET`: packet expression to validate, serialize, and transmit.
- `PACKET_COUNT`: optional positive integer cap for the number of generated
  packets.
- `PMD_THREADS`: optional positive integer for live mode. When set, DPDK must
  expose at least that many worker lcores through `DPDK_ARGS`; for example,
  `PMD_THREADS: 2` requires a lcore list such as `-l 0-2`.
- `TX_BATCH_SIZE`: optional positive integer for live mode transmit batching.
  The default is 32 and the current maximum is 256.

Ranges are accepted for IPv4/IPv6 address fields and range-capable integer
fields such as TCP/UDP ports.

In multi-PMD live mode, each PMD worker emits the same planned range sequence in
the first implementation. Mbufs are seeded with the base packet format when the
mempool is created; workers allocate batches, reset cheap mbuf metadata, apply
the range modifiers for each flow index, fix lengths/checksums, and transmit the
batch.

## Build

FlowForge uses CMake and C++20. By default, the build downloads and builds the
bundled DPDK release.

Typical Linux dependencies include:

- CMake 3.20+
- a C++20 compiler
- Meson
- Git
- `pkg-config` or `pkgconf`
- Python 3 with `pyelftools`
- `libnuma` development headers
- rdma-core development headers and libraries when building mlx5 support

Build:

```sh
cmake -S . -B build
cmake --build build -j2
```

To build a mostly-static deployable `ffg` with DPDK mlx5 support:

```sh
cmake -S . -B build -DPACKET_STATIC_DEPLOY=ON
cmake --build build --target ffg_deploy -j2
```

This stages `ffg` and DPDK's mlx5 glue library under `build/deploy/`. The
binary statically links the C++ runtime and bundled DPDK archives, while glibc,
`libnuma`, and rdma-core libraries such as `libibverbs.so` and `libmlx5.so`
remain host-provided. If the glue library is not in the default loader path,
run with `MLX5_GLUE_PATH` pointing at the deploy directory.

To build only the parser/checker/serializer library and unit tests without DPDK:

```sh
cmake -S . -B build -DPACKET_BUILD_DPDK=OFF
cmake --build build -j2
```

## Run

Run a packet program with the DPDK tap runtime:

```sh
./build/ffg examples/tap_runtime.packet
./build/ffg examples/tap_runtime.packet --clone 4
./build/ffg examples/tap_runtime.packet --once
```

The current tap runtime creates the tap interface `packet_tap0`. Creating and
capturing from tap interfaces generally requires root or equivalent network
capabilities.

Live mode runs continuously by default: each worker cycles through the planned
range, applies `--clone N` copies for each generated packet format, and then
starts the range again. Use `--once` for finite test-style runs that transmit
one pass and exit. With multiple `PMD_THREADS`, workers duplicate the planned
range by default. Add `--split` to partition the planned flow formats across
PMD workers instead; when the range count is not divisible by the worker count,
earlier workers receive one extra flow format.

Write generated packets to a pcap file without starting DPDK:

```sh
./build/ffg examples/tap_runtime.packet -o flows.pcap
./build/ffg -e 'Ether()/IP(src="[10.0.0.1-10.0.0.4]")/UDP()' -o flows.pcap -c 2
./build/ffg -e 'Ether()/IP(src="[10.0.0.1-10.0.0.4]")/UDP()' -o flows.pcap -c 2 --clone 3
```

When `-o` is present, `ffg` enters file mode. File mode accepts either a packet
program file or an inline packet expression with `-e`. A leading `PACKET:` in
the `-e` expression is accepted but not required. `PACKET_COUNT` in a program
file or `-c` on the command line caps range expansion; specifying both is an
error. The `--clone` option multiplies emitted packets after this cap, so
`-c 2 --clone 3` writes six packets. File mode writes pcap directly and does
not link libpcap or initialize DPDK.

Example output:

```text
DPDK runtime completed; rte_eal_init parsed ... argument(s), port 0 sent 3/3 packet(s), planned 3 of 3 flow(s), packet_len 42 bytes
```

## Test

Run the C++ unit tests:

```sh
ctest --test-dir build --output-on-failure
```

The end-to-end tests are opt-in because they require Linux tap support, Scapy,
and root or equivalent network capabilities. They create a Python virtual
environment under the build directory and install the e2e requirements there.

```sh
cmake -S . -B build -DPACKET_BUILD_E2E_TESTS=ON
cmake --build build -j2
ctest --test-dir build -R E2ETest --output-on-failure
```

Run the e2e pytest suite directly through the Python wrapper:

```sh
python3 tests/e2e/run_pytest.py \
  --venv build/e2e-venv \
  --requirements tests/e2e/requirements.txt \
  --runtime build/ffg \
  -- tests/e2e
```

The e2e suite launches `ffg`, captures packets from `packet_tap0`
with Scapy, reloads Scapy's interface cache between runs, and validates normal
IPv4 TCP/UDP/ICMP packets, VXLAN encapsulation, IP/TCP options, and flow range
expansion.

## Project Layout

- `include/packet/`: public C++ headers.
- `src/`: parser, checker, constructor, serializer, registry, and runtime code.
- `apps/`: runtime command-line entrypoints.
- `tests/`: C++ unit tests and pytest/Scapy e2e tests.
- `examples/`: sample packet programs.
