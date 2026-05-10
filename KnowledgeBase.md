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
