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

## Live mode performance and TX batching

A single-flow live-mode test (`flows=1`, `TX_BATCH_SIZE=32`) originally produced
only ~2.7 Mpps on a single core, while the same configuration with
`sport=[1-1000]` (`flows=1000`) reached ~13 Mpps. Profiling showed most CPU
time in `packet::fixup_packet`, but the real bottleneck was not the fixup code.

Root cause: `run_worker()` computed

```cpp
planned_transmissions = flow_count * clone_count;
```

and used it to cap both the batch size and the flow index:

```cpp
const auto count = std::min<uint64_t>(context.batch_size, remaining);
```

With `flows=1` and the default `clone_count=1`, `planned_transmissions=1`, so
every DPDK TX burst sent exactly one packet. DPDK's burst API is designed for
multi-packet batches; single-packet bursts spend most of their time on
descriptor-ring and doorbell overhead that cannot be amortized.

Fix:

- Split the worker into two paths:
  - `run_worker_once()` for `--once`: sends exactly
    `flow_count * clone_count` packets and exits.
  - `run_worker()` for live mode: always uses the full `TX_BATCH_SIZE`, and
    cycles `flow_index` with modulo arithmetic so flows are reused
    indefinitely:

    ```cpp
    flow_index = first_flow +
                 (local_transmission / clone_count) % flow_count;
    ```

- Choose the function at launch time:

  ```cpp
  const auto worker_fn = context.once ? run_worker_once : run_worker;
  rte_eal_remote_launch(worker_fn, &context, lcores[worker]);
  ```

Result: single-flow live mode now reaches ~13 Mpps, matching the multi-flow
case, because every DPDK TX burst sends 32 packets instead of 1.

Rule of thumb for live-mode tuning: if `flow_count * clone_count` is small,
the old code path silently degraded TX batching. The new code path ignores
that product for batch sizing and only uses it to decide the flow sequence.
