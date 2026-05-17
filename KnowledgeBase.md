# Knowledge Base

## DPDK `net/pcap`, libpcap, and file output

DPDK provides a `net/pcap` virtual PMD that can write transmitted packets to a
pcap file with options such as `tx_pcap=...`. That path depends on libpcap.

For this project, libpcap is intentionally avoided in the DPDK build. Static
linking with libpcap pulls in too many transitive system dependencies and makes
static DPDK builds difficult to reproduce. The local DPDK patch changes DPDK's
build system so libpcap is not linked when the `net/pcap` driver is disabled.

Project policy:

- Keep live traffic generation on the DPDK runtime path.
- Keep `net/pcap` disabled in the bundled DPDK configuration.
- Do not link `ffg` against libpcap for pcap file generation.
- Generate pcap files from the DPDK-free parser, checker, constructor,
  serializer, and range-expansion code instead.

This keeps file output available in `PACKET_BUILD_DPDK=OFF` builds and avoids
reintroducing libpcap into the static DPDK link.

## Static linking and binary portability

A project goal is to produce a mostly self-contained `ffg` binary via static
linking. The deployment build statically links the C++ runtime and bundled DPDK
archives, while keeping glibc dynamic so the binary remains compatible with the
supported production distro family.

All external dependencies (DPDK, GoogleTest) are built from source alongside the
project to avoid accidental dynamic linkage against system-provided versions.

## Mellanox NIC support

The production environment uses Mellanox ConnectX NICs (ConnectX-5, ConnectX-6,
ConnectX-7). The deployment build enables DPDK's `mlx5` PMD with
`ibverbs_link=dlopen`, stages DPDK's `librte_common_mlx5_glue.so.*` beside
`ffg`, and still relies on host-provided rdma-core shared libraries such as
`libibverbs.so` and `libmlx5.so`. Set `MLX5_GLUE_PATH` to the deploy directory
when the glue library is not in the default loader path.
