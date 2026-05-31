#include "packet/runtime.hpp"

#include "packet/dpdk_offload.hpp"
#include "packet/packet_generator.hpp"
#include "packet/pcap_writer.hpp"
#include "packet/stats_format.hpp"

#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <format>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#ifdef __linux__
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace packet {

namespace {

constexpr uint16_t runtime_port_id = 0;
constexpr uint16_t runtime_queue_id = 0;
constexpr uint16_t runtime_rx_descriptors = 128;
constexpr uint16_t runtime_tx_descriptors = 512;
constexpr unsigned runtime_mbuf_cache_size = 250;
constexpr uint16_t runtime_default_tx_batch_size = 32;
constexpr uint16_t runtime_max_tx_batch_size = 256;
constexpr uint16_t runtime_rx_batch_size = 32;
constexpr uint16_t runtime_max_rx_batch_size = 128;
constexpr std::string_view runtime_tap_name = "net_tap0";
constexpr std::string_view runtime_tap_args = "iface=packet_tap0,mac=fixed";
constexpr std::string_view runtime_tap_iface = "packet_tap0";

constexpr size_t cache_line_size = 64;

std::atomic_bool runtime_stop_requested = false;

void request_runtime_stop(int) {
    runtime_stop_requested.store(true, std::memory_order_relaxed);
}

class SignalGuard {
public:
    SignalGuard() {
        runtime_stop_requested.store(false, std::memory_order_relaxed);
        old_int_ = std::signal(SIGINT, request_runtime_stop);
        old_term_ = std::signal(SIGTERM, request_runtime_stop);
    }

    SignalGuard(const SignalGuard&) = delete;
    SignalGuard& operator=(const SignalGuard&) = delete;

    ~SignalGuard() {
        std::signal(SIGINT, old_int_);
        std::signal(SIGTERM, old_term_);
    }

private:
    using Handler = void (*)(int);

    Handler old_int_ = SIG_DFL;
    Handler old_term_ = SIG_DFL;
};

std::vector<char*> make_eal_argv(std::vector<std::string>& argv_storage) {
    std::vector<char*> argv;
    argv.reserve(argv_storage.size());
    for (auto& arg : argv_storage) {
        argv.push_back(arg.data());
    }
    return argv;
}

std::vector<std::string> make_eal_argv_storage(std::vector<std::string> dpdk_args,
                                               std::string_view eal_program_name) {
    std::vector<std::string> argv_storage;
    argv_storage.reserve(dpdk_args.size() + 1);
    argv_storage.emplace_back(eal_program_name);
    argv_storage.insert(argv_storage.end(),
                        std::make_move_iterator(dpdk_args.begin()),
                        std::make_move_iterator(dpdk_args.end()));
    return argv_storage;
}

int init_eal(std::vector<std::string> dpdk_args,
             std::string_view eal_program_name,
             Runtime::Result& result) {
    auto argv_storage = make_eal_argv_storage(std::move(dpdk_args), eal_program_name);
    auto argv = make_eal_argv(argv_storage);

    const int parsed_args = rte_eal_init(static_cast<int>(argv.size()), argv.data());
    if (parsed_args < 0) {
        result.errors.push_back(std::format("rte_eal_init failed: {}", rte_strerror(rte_errno)));
        return parsed_args;
    }

    result.eal_parsed_args = parsed_args;
    return parsed_args;
}

struct MempoolDeleter {
    void operator()(rte_mempool* pool) const {
        if (pool != nullptr) {
            rte_mempool_free(pool);
        }
    }
};

using MempoolPtr = std::unique_ptr<rte_mempool, MempoolDeleter>;

struct MempoolSeedContext {
    std::span<const std::byte> base_payload;
    uint32_t seeded = 0;
};

void seed_mbuf_base_payload(rte_mempool*, void* opaque, void* object, unsigned) {
    auto& context = *static_cast<MempoolSeedContext*>(opaque);
    auto* mbuf = static_cast<rte_mbuf*>(object);
    void* packet_data = rte_pktmbuf_mtod(mbuf, void*);
    std::memcpy(packet_data, context.base_payload.data(), context.base_payload.size());
    ++context.seeded;
}

struct WorkerStats {
    uint64_t tx_attempted = 0;
    uint64_t tx_sent = 0;
    std::vector<std::string> errors;
};

struct PublishedWorkerStats {
    std::atomic<uint64_t> tx_attempted{0};
    std::atomic<uint64_t> tx_sent{0};
    uint8_t pad[cache_line_size - 2 * sizeof(std::atomic<uint64_t>)]{};

    PublishedWorkerStats() = default;
    PublishedWorkerStats(PublishedWorkerStats&& other) noexcept
        : tx_attempted{other.tx_attempted.load(std::memory_order_relaxed)},
          tx_sent{other.tx_sent.load(std::memory_order_relaxed)}
    {
    }
    PublishedWorkerStats& operator=(PublishedWorkerStats&& other) noexcept {
        tx_attempted.store(other.tx_attempted.load(std::memory_order_relaxed), std::memory_order_relaxed);
        tx_sent.store(other.tx_sent.load(std::memory_order_relaxed), std::memory_order_relaxed);
        return *this;
    }
    PublishedWorkerStats(const PublishedWorkerStats&) = delete;
    PublishedWorkerStats& operator=(const PublishedWorkerStats&) = delete;
};
static_assert(sizeof(PublishedWorkerStats) == cache_line_size);

struct PublishedRxWorkerStats {
    std::atomic<uint64_t> rx_received{0};
    std::atomic<uint64_t> rx_bytes{0};
    uint8_t pad[cache_line_size - 2 * sizeof(std::atomic<uint64_t>)]{};

    PublishedRxWorkerStats() = default;
    PublishedRxWorkerStats(PublishedRxWorkerStats&& other) noexcept
        : rx_received{other.rx_received.load(std::memory_order_relaxed)},
          rx_bytes{other.rx_bytes.load(std::memory_order_relaxed)}
    {
    }
    PublishedRxWorkerStats& operator=(PublishedRxWorkerStats&& other) noexcept {
        rx_received.store(other.rx_received.load(std::memory_order_relaxed), std::memory_order_relaxed);
        rx_bytes.store(other.rx_bytes.load(std::memory_order_relaxed), std::memory_order_relaxed);
        return *this;
    }
    PublishedRxWorkerStats(const PublishedRxWorkerStats&) = delete;
    PublishedRxWorkerStats& operator=(const PublishedRxWorkerStats&) = delete;
};
static_assert(sizeof(PublishedRxWorkerStats) == cache_line_size);

struct WorkerContext {
    uint64_t worker_id = 0;
    uint64_t lcore_id = 0;
    uint16_t port_id = 0;
    uint16_t queue_id = 0;
    uint64_t first_flow = 0;
    uint64_t flow_count = 0;
    uint64_t clone_count = 1;
    bool once = false;
    bool split = false;
    const std::atomic_bool* stop_requested = nullptr;
    rte_mempool* mbuf_pool = nullptr;
    const PacketGenerator* generator = nullptr;
    const GeneratedPacket* packet = nullptr;
    uint16_t batch_size = runtime_default_tx_batch_size;
    uint64_t total_pmd_threads = 1;
    std::optional<uint64_t> stats_interval_seconds;
    PublishedWorkerStats* published_stats = nullptr;
    WorkerStats stats;
};

struct RxWorkerStats {
    uint64_t rx_received = 0;
    uint64_t rx_bytes = 0;
};

struct RxWorkerContext {
    uint64_t worker_id = 0;
    uint64_t lcore_id = 0;
    uint16_t port_id = 0;
    uint16_t queue_id = 0;
    const std::atomic_bool* stop_requested = nullptr;
    uint16_t batch_size = runtime_rx_batch_size;
    PublishedRxWorkerStats* published_stats = nullptr;
    RxWorkerStats stats;
};

#ifdef __linux__
class Fd {
public:
    explicit Fd(int fd)
        : fd_(fd)
    {
    }

    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;

    ~Fd() {
        if (fd_ >= 0) {
            close(fd_);
        }
    }

    int get() const {
        return fd_;
    }

private:
    int fd_ = -1;
};
#endif

unsigned mbuf_count_for(uint64_t worker_count, uint16_t batch_size) {
    const auto in_flight = worker_count * (runtime_tx_descriptors + batch_size * 2ull);
    return static_cast<unsigned>(std::max<uint64_t>(8191, in_flight + runtime_mbuf_cache_size));
}

MempoolPtr make_mbuf_pool(const GeneratedPacket& packet,
                          uint64_t worker_count,
                          uint16_t batch_size,
                          Runtime::Result& result) {
    rte_mempool* pool = rte_pktmbuf_pool_create("packet_runtime_mbuf_pool",
                                                mbuf_count_for(worker_count, batch_size),
                                                runtime_mbuf_cache_size,
                                                0,
                                                RTE_MBUF_DEFAULT_BUF_SIZE,
                                                rte_socket_id());
    if (pool == nullptr) {
        result.errors.push_back(std::format("rte_pktmbuf_pool_create failed: {}",
                                            rte_strerror(rte_errno)));
        return MempoolPtr{pool};
    }

    MempoolSeedContext seed{packet.base_payload};
    const auto iterated = rte_mempool_obj_iter(pool, seed_mbuf_base_payload, &seed);
    if (iterated == 0 || seed.seeded != iterated) {
        result.errors.push_back("failed to seed packet base payload into the mbuf pool");
    }
    return MempoolPtr{pool};
}

bool check_tap_permission(Runtime::Result& result) {
#ifdef __linux__
    Fd tun_fd{open("/dev/net/tun", O_RDWR)};
    if (tun_fd.get() < 0) {
        result.errors.push_back(std::format("failed to open /dev/net/tun for TAP preflight: {}",
                                            std::strerror(errno)));
        return false;
    }

    ifreq request{};
    request.ifr_flags = IFF_TAP | IFF_NO_PI;
    std::strncpy(request.ifr_name, runtime_tap_iface.data(), IFNAMSIZ - 1);

    if (ioctl(tun_fd.get(), TUNSETIFF, &request) < 0) {
        result.errors.push_back(std::format("failed to create TAP interface '{}' during preflight: {}",
                                            runtime_tap_iface,
                                            std::strerror(errno)));
        return false;
    }
#endif
    return true;
}

bool probe_tap_port(Runtime::Result& result) {
    int rc = rte_eal_hotplug_add("vdev", runtime_tap_name.data(), runtime_tap_args.data());
    if (rc < 0) {
        result.errors.push_back(std::format("failed to create TAP port '{}': {}",
                                            runtime_tap_name,
                                            rte_strerror(-rc)));
        return false;
    }
    return true;
}

bool configure_and_start_port(uint16_t port_id,
                              uint16_t rx_queue_count,
                              uint16_t tx_queue_count,
                              rte_mempool& mbuf_pool,
                              Runtime::Result& result) {
    const uint16_t port_count = rte_eth_dev_count_avail();
    if (port_count == 0) {
        result.errors.emplace_back("no DPDK ethdev ports are available");
        return false;
    }
    if (port_id >= port_count) {
        result.errors.push_back(std::format("requested DPDK port {} but only {} port(s) are available",
                                            port_id,
                                            port_count));
        return false;
    }

    rte_eth_conf port_conf{};
    int rc = rte_eth_dev_configure(port_id, rx_queue_count, tx_queue_count, &port_conf);
    if (rc < 0) {
        result.errors.push_back(std::format("rte_eth_dev_configure failed for port {}: {}",
                                            port_id,
                                            rte_strerror(-rc)));
        return false;
    }

    for (uint16_t queue_id = 0; queue_id < rx_queue_count; ++queue_id) {
        rc = rte_eth_rx_queue_setup(port_id,
                                    queue_id,
                                    runtime_rx_descriptors,
                                    rte_eth_dev_socket_id(port_id),
                                    nullptr,
                                    &mbuf_pool);
        if (rc < 0) {
            result.errors.push_back(std::format("rte_eth_rx_queue_setup failed for port {} queue {}: {}",
                                                port_id,
                                                queue_id,
                                                rte_strerror(-rc)));
            return false;
        }
    }

    for (uint16_t queue_id = 0; queue_id < tx_queue_count; ++queue_id) {
        rc = rte_eth_tx_queue_setup(port_id,
                                    queue_id,
                                    runtime_tx_descriptors,
                                    rte_eth_dev_socket_id(port_id),
                                    nullptr);
        if (rc < 0) {
            result.errors.push_back(std::format("rte_eth_tx_queue_setup failed for port {} queue {}: {}",
                                                port_id,
                                                queue_id,
                                                rte_strerror(-rc)));
            return false;
        }
    }

    rc = rte_eth_dev_start(port_id);
    if (rc < 0) {
        result.errors.push_back(std::format("rte_eth_dev_start failed for port {}: {}",
                                            port_id,
                                            rte_strerror(-rc)));
        return false;
    }

    result.port_id = port_id;
    return true;
}

void free_unsent(rte_mbuf** packets, uint16_t begin, uint16_t end) {
    for (uint16_t index = begin; index < end; ++index) {
        rte_pktmbuf_free(packets[index]);
    }
}

bool prepare_batch_packet(WorkerContext& context,
                          rte_mbuf& mbuf,
                          uint64_t flow_index) {
    void* packet_data = rte_pktmbuf_append(&mbuf, static_cast<uint16_t>(context.packet->packet_len));
    if (packet_data == nullptr) {
        context.stats.errors.push_back(std::format("packet length {} does not fit in an mbuf",
                                                   context.packet->packet_len));
        return false;
    }

    mbuf.ol_flags = 0;
    mbuf.l2_len = 0;
    mbuf.l3_len = 0;
    mbuf.l4_len = 0;

    auto payload = std::span{static_cast<std::byte*>(packet_data), context.packet->packet_len};
    if (!context.generator->apply_flow(*context.packet, flow_index, payload, context.stats.errors)) {
        return false;
    }

    apply_dpdk_offload_request(mbuf, context.packet->fixup_plan.offload);
    return true;
}

void publish_worker_stats(const WorkerContext& context) {
    if (context.published_stats == nullptr) {
        return;
    }
    context.published_stats->tx_attempted.store(context.stats.tx_attempted, std::memory_order_relaxed);
    context.published_stats->tx_sent.store(context.stats.tx_sent, std::memory_order_relaxed);
}

void publish_rx_worker_stats(const RxWorkerContext& context) {
    if (context.published_stats == nullptr) {
        return;
    }
    context.published_stats->rx_received.store(context.stats.rx_received, std::memory_order_relaxed);
    context.published_stats->rx_bytes.store(context.stats.rx_bytes, std::memory_order_relaxed);
}

bool transmit_batch(WorkerContext& context,
                    std::span<rte_mbuf*> packets) {
    const auto packet_count = static_cast<uint16_t>(packets.size());
    context.stats.tx_attempted += packet_count;

    const uint16_t prepared = rte_eth_tx_prepare(context.port_id,
                                                context.queue_id,
                                                packets.data(),
                                                packet_count);
    if (prepared != packet_count) {
        free_unsent(packets.data(), prepared, packet_count);
        context.stats.errors.push_back(std::format("rte_eth_tx_prepare prepared {} of {} packet(s)",
                                                   prepared,
                                                   packet_count));
        if (prepared == 0) {
            return false;
        }
    }

    uint16_t sent_total = 0;
    while (sent_total < prepared) {
        const uint16_t sent = rte_eth_tx_burst(context.port_id,
                                              context.queue_id,
                                              packets.data() + sent_total,
                                              static_cast<uint16_t>(prepared - sent_total));
        if (sent == 0) {
            break;
        }
        sent_total += sent;
    }

    context.stats.tx_sent += sent_total;
    if (sent_total != prepared) {
        free_unsent(packets.data(), sent_total, prepared);
        context.stats.errors.push_back(std::format("rte_eth_tx_burst sent {} of {} prepared packet(s)",
                                                   sent_total,
                                                   prepared));
        return false;
    }

    return prepared == packet_count;
}

struct WorkerStatsView {
    uint64_t worker_id = 0;
    uint64_t lcore_id = 0;
    uint16_t queue_id = 0;
    uint64_t first_flow = 0;
    uint64_t flow_count = 0;
    uint64_t tx_attempted = 0;
    uint64_t tx_sent = 0;
};

struct RxWorkerStatsView {
    uint64_t worker_id = 0;
    uint64_t lcore_id = 0;
    uint16_t queue_id = 0;
    uint64_t rx_received = 0;
    uint64_t rx_bytes = 0;
    uint64_t rx_errors = 0;
};

WorkerStatsView make_worker_stats_view(const WorkerContext& context) {
    WorkerStatsView view;
    view.worker_id = context.worker_id;
    view.lcore_id = context.lcore_id;
    view.queue_id = context.queue_id;
    view.first_flow = context.first_flow;
    view.flow_count = context.flow_count;
    if (context.published_stats != nullptr) {
        view.tx_attempted = context.published_stats->tx_attempted.load(std::memory_order_relaxed);
        view.tx_sent = context.published_stats->tx_sent.load(std::memory_order_relaxed);
    } else {
        view.tx_attempted = context.stats.tx_attempted;
        view.tx_sent = context.stats.tx_sent;
    }
    return view;
}

RxWorkerStatsView make_rx_worker_stats_view(const RxWorkerContext& context) {
    RxWorkerStatsView view;
    view.worker_id = context.worker_id;
    view.lcore_id = context.lcore_id;
    view.queue_id = context.queue_id;
    if (context.published_stats != nullptr) {
        view.rx_received = context.published_stats->rx_received.load(std::memory_order_relaxed);
        view.rx_bytes = context.published_stats->rx_bytes.load(std::memory_order_relaxed);
    } else {
        view.rx_received = context.stats.rx_received;
        view.rx_bytes = context.stats.rx_bytes;
    }
    return view;
}

class LiveStatsDisplay {
public:
    explicit LiveStatsDisplay(uint64_t interval_seconds)
        : interval_(std::chrono::seconds{interval_seconds}),
          start_(std::chrono::steady_clock::now()),
          last_(start_),
          next_(start_ + interval_)
    {
    }

    // Overload for single TX worker on main lcore (no RX workers)
    bool refresh_if_due(std::span<const WorkerStatsView> workers,
                        size_t packet_len,
                        uint64_t pmd_threads,
                        uint64_t tx_batch_size,
                        uint64_t clone_count,
                        bool split,
                        bool once) {
        const auto now = std::chrono::steady_clock::now();
        if (now < next_) {
            return false;
        }
        refresh(workers,
                {},
                0,
                0,
                packet_len,
                pmd_threads,
                0,
                tx_batch_size,
                clone_count,
                split,
                once,
                now);
        do {
            next_ += interval_;
        } while (next_ <= now);
        return true;
    }

    bool refresh_if_due(std::span<const WorkerStatsView> tx_workers,
                        std::span<const RxWorkerStatsView> rx_workers,
                        uint64_t port_imissed,
                        uint64_t port_ierrors,
                        size_t packet_len,
                        uint64_t tx_threads,
                        uint64_t rx_threads,
                        uint64_t tx_batch_size,
                        uint64_t clone_count,
                        bool split,
                        bool once) {
        const auto now = std::chrono::steady_clock::now();
        if (now < next_) {
            return false;
        }
        refresh(tx_workers,
                rx_workers,
                port_imissed,
                port_ierrors,
                packet_len,
                tx_threads,
                rx_threads,
                tx_batch_size,
                clone_count,
                split,
                once,
                now);
        do {
            next_ += interval_;
        } while (next_ <= now);
        return true;
    }

private:
    void refresh(std::span<const WorkerStatsView> tx_workers,
                 std::span<const RxWorkerStatsView> rx_workers,
                 uint64_t port_imissed,
                 uint64_t port_ierrors,
                 size_t packet_len,
                 uint64_t tx_threads,
                 uint64_t rx_threads,
                 uint64_t tx_batch_size,
                 uint64_t clone_count,
                 bool split,
                 bool once,
                 std::chrono::steady_clock::time_point now) {
        if (previous_tx_sent_.size() != tx_workers.size()) {
            previous_tx_sent_.assign(tx_workers.size(), 0);
        }
        if (previous_rx_received_.size() != rx_workers.size()) {
            previous_rx_received_.assign(rx_workers.size(), 0);
        }

        const auto elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(now - start_).count();
        const auto sample_seconds = std::chrono::duration<double>(now - last_).count();
        last_ = now;

        // TX totals
        uint64_t total_tx_sent = 0;
        uint64_t total_tx_attempted = 0;
        uint64_t total_tx_delta = 0;
        std::vector<uint64_t> tx_deltas;
        tx_deltas.reserve(tx_workers.size());
        for (size_t index = 0; index < tx_workers.size(); ++index) {
            const auto& worker = tx_workers[index];
            total_tx_sent += worker.tx_sent;
            total_tx_attempted += worker.tx_attempted;
            const auto previous = previous_tx_sent_[index];
            const auto delta = worker.tx_sent >= previous ? worker.tx_sent - previous : uint64_t{0};
            previous_tx_sent_[index] = worker.tx_sent;
            total_tx_delta += delta;
            tx_deltas.push_back(delta);
        }

        const auto total_tx_pps = sample_seconds > 0.0 ? static_cast<double>(total_tx_delta) / sample_seconds : 0.0;
        const auto total_tx_bps = total_tx_pps * static_cast<double>(packet_len) * 8.0;

        // RX totals
        uint64_t total_rx_received = 0;
        uint64_t total_rx_bytes = 0;
        uint64_t total_rx_delta = 0;
        std::vector<uint64_t> rx_deltas;
        rx_deltas.reserve(rx_workers.size());
        for (size_t index = 0; index < rx_workers.size(); ++index) {
            const auto& worker = rx_workers[index];
            total_rx_received += worker.rx_received;
            total_rx_bytes += worker.rx_bytes;
            const auto previous = previous_rx_received_[index];
            const auto delta = worker.rx_received >= previous ? worker.rx_received - previous : uint64_t{0};
            previous_rx_received_[index] = worker.rx_received;
            total_rx_delta += delta;
            rx_deltas.push_back(delta);
        }

        const auto total_rx_pps = sample_seconds > 0.0 ? static_cast<double>(total_rx_delta) / sample_seconds : 0.0;
        const auto total_rx_bps = total_rx_pps * static_cast<double>(packet_len) * 8.0;

        const auto imiss_delta = port_imissed >= previous_imissed_ ? port_imissed - previous_imissed_ : uint64_t{0};
        const auto ierrors_delta = port_ierrors >= previous_ierrors_ ? port_ierrors - previous_ierrors_ : uint64_t{0};
        previous_imissed_ = port_imissed;
        previous_ierrors_ = port_ierrors;

        std::cout << "\033[2J\033[H"
                  << "FlowForge live stats\n\n"
                  << "elapsed: " << format_elapsed_seconds(static_cast<uint64_t>(elapsed_seconds)) << '\n'
                  << "packet_len: " << packet_len << " bytes\n"
                  << "tx_queues: " << tx_threads << "    rx_queues: " << rx_threads << '\n'
                  << "tx_batch_size: " << tx_batch_size << "    clone_count: " << clone_count << '\n'
                  << "split: " << (split ? "on" : "off") << "      once: " << (once ? "on" : "off") << "\n\n";

        // TX table
        if (!tx_workers.empty()) {
            std::cout << "tx workers:\n"
                      << std::format("  {:<4}{:<8}{:<8}{:<14}{:<14}{:<14}{:<12}{}\n",
                                     "id",
                                     "lcore",
                                     "queue",
                                     "flows",
                                     "sent",
                                     "attempted",
                                     "pps",
                                     "bps");

            for (size_t index = 0; index < tx_workers.size(); ++index) {
                const auto& worker = tx_workers[index];
                const auto worker_pps = sample_seconds > 0.0
                    ? static_cast<double>(tx_deltas[index]) / sample_seconds
                    : 0.0;
                const auto worker_bps = worker_pps * static_cast<double>(packet_len) * 8.0;
                std::cout << std::format("  {:<4}{:<8}{:<8}{:<14}{:<14}{:<14}{:<12}{}\n",
                                         worker.worker_id,
                                         worker.lcore_id,
                                         worker.queue_id,
                                         std::format("{}+{}", worker.first_flow, worker.flow_count),
                                         format_human_count(static_cast<double>(worker.tx_sent)),
                                         format_human_count(static_cast<double>(worker.tx_attempted)),
                                         format_human_rate(worker_pps, "pps"),
                                         format_human_rate(worker_bps, "bps"));
            }
            std::cout << "  tx total: " << format_human_count(static_cast<double>(total_tx_sent))
                      << " packets, " << format_human_rate(total_tx_pps, "pps")
                      << ", " << format_human_rate(total_tx_bps, "bps") << "\n\n";
        }

        // RX table
        if (!rx_workers.empty()) {
            std::cout << "rx workers:\n"
                      << std::format("  {:<4}{:<8}{:<8}{:<14}{:<14}{:<12}{:<12}{}\n",
                                     "id",
                                     "lcore",
                                     "queue",
                                     "received",
                                     "bytes",
                                     "pps",
                                     "bps",
                                     "imiss");

            for (size_t index = 0; index < rx_workers.size(); ++index) {
                const auto& worker = rx_workers[index];
                const auto worker_pps = sample_seconds > 0.0
                    ? static_cast<double>(rx_deltas[index]) / sample_seconds
                    : 0.0;
                const auto worker_bps = worker_pps * static_cast<double>(packet_len) * 8.0;
                std::cout << std::format("  {:<4}{:<8}{:<8}{:<14}{:<14}{:<12}{:<12}{}\n",
                                         worker.worker_id,
                                         worker.lcore_id,
                                         worker.queue_id,
                                         format_human_count(static_cast<double>(worker.rx_received)),
                                         format_human_count(static_cast<double>(worker.rx_bytes)),
                                         format_human_rate(worker_pps, "pps"),
                                         format_human_rate(worker_bps, "bps"),
                                         format_human_count(static_cast<double>(port_imissed)));
            }
            std::cout << "  rx total: " << format_human_count(static_cast<double>(total_rx_received))
                      << " packets, " << format_human_count(static_cast<double>(total_rx_bytes))
                      << " bytes, " << format_human_rate(total_rx_pps, "pps")
                      << ", " << format_human_rate(total_rx_bps, "bps")
                      << ", imiss: " << format_human_count(static_cast<double>(imiss_delta))
                      << ", errors: " << format_human_count(static_cast<double>(ierrors_delta)) << "\n\n";
        }

        std::cout.flush();
    }

    std::chrono::seconds interval_;
    std::chrono::steady_clock::time_point start_;
    std::chrono::steady_clock::time_point last_;
    std::chrono::steady_clock::time_point next_;
    std::vector<uint64_t> previous_tx_sent_;
    std::vector<uint64_t> previous_rx_received_;
    uint64_t previous_imissed_ = 0;
    uint64_t previous_ierrors_ = 0;
};

uint64_t checked_transmission_count(uint64_t flow_count,
                                    uint64_t clone_count,
                                    Runtime::Result& result) {
    if (clone_count == 0) {
        result.errors.emplace_back("clone count must be positive");
        return 0;
    }
    if (flow_count > std::numeric_limits<uint64_t>::max() / clone_count) {
        result.errors.emplace_back("clone expansion has more than 18446744073709551615 packets");
        return 0;
    }
    return flow_count * clone_count;
}

uint64_t checked_total_transmission_count(uint64_t planned_flows,
                                          uint64_t worker_count,
                                          const Runtime::RunOptions& options,
                                          Runtime::Result& result) {
    const auto per_worker = checked_transmission_count(planned_flows, options.clone_count, result);
    if (!result.errors.empty()) {
        return 0;
    }
    if (options.split) {
        return per_worker;
    }
    if (per_worker > std::numeric_limits<uint64_t>::max() / worker_count) {
        result.errors.emplace_back("worker expansion has more than 18446744073709551615 packets");
        return 0;
    }
    return per_worker * worker_count;
}

FixupOptions live_fixup_options() {
    FixupOptions options;
    options.ipv4_checksum = FixupMode::HardwareOffload;
    options.tcp_checksum = FixupMode::HardwareOffload;
    options.udp_checksum = FixupMode::HardwareOffload;
    options.icmp_checksum = FixupMode::Software;
    return options;
}

struct FlowRange {
    uint64_t first = 0;
    uint64_t count = 0;
};

FlowRange assigned_flow_range(uint64_t planned_flows,
                              uint64_t worker_count,
                              uint64_t worker_id,
                              bool split) {
    if (!split) {
        return FlowRange{0, planned_flows};
    }

    const auto base = planned_flows / worker_count;
    const auto extra = planned_flows % worker_count;
    const auto count = base + (worker_id < extra ? 1 : 0);
    const auto first = worker_id * base + std::min(worker_id, extra);
    return FlowRange{first, count};
}

int run_worker(void* arg) {
    auto& context = *static_cast<WorkerContext*>(arg);
    std::array<rte_mbuf*, runtime_max_tx_batch_size> batch{};
    const auto planned_transmissions = context.flow_count * context.clone_count;
    if (planned_transmissions == 0) {
        return 0;
    }

    std::optional<LiveStatsDisplay> stats_display;
    if (context.stats_interval_seconds && context.total_pmd_threads == 1) {
        stats_display.emplace(*context.stats_interval_seconds);
    }

    do {
        uint64_t transmitted = 0;
        while (transmitted < planned_transmissions &&
               (context.stop_requested == nullptr ||
                !context.stop_requested->load(std::memory_order_relaxed))) {
            const auto remaining = planned_transmissions - transmitted;
            const auto count = static_cast<uint16_t>(std::min<uint64_t>(context.batch_size, remaining));
            if (rte_pktmbuf_alloc_bulk(context.mbuf_pool, batch.data(), count) != 0) {
                context.stats.errors.push_back(std::format("rte_pktmbuf_alloc_bulk failed for {} packet(s): {}",
                                                           count,
                                                           rte_strerror(rte_errno)));
                return 1;
            }

            uint16_t prepared_count = 0;
            for (; prepared_count < count; ++prepared_count) {
                const auto local_transmission = transmitted + prepared_count;
                const auto flow_index = context.first_flow + local_transmission / context.clone_count;
                if (!prepare_batch_packet(context, *batch[prepared_count], flow_index)) {
                    free_unsent(batch.data(), 0, count);
                    return 1;
                }
            }

            if (!transmit_batch(context, std::span{batch.data(), count})) {
                publish_worker_stats(context);
                return 1;
            }
            publish_worker_stats(context);
            transmitted += count;

            if (stats_display) {
                const auto view = make_worker_stats_view(context);
                stats_display->refresh_if_due(std::span{&view, 1},
                                              context.packet->packet_len,
                                              context.total_pmd_threads,
                                              context.batch_size,
                                              context.clone_count,
                                              context.split,
                                              context.once);
            }
        }
    } while (!context.once &&
             (context.stop_requested == nullptr ||
              !context.stop_requested->load(std::memory_order_relaxed)));

    return 0;
}

int run_rx_worker(void* arg) {
    auto& context = *static_cast<RxWorkerContext*>(arg);
    std::array<rte_mbuf*, runtime_max_rx_batch_size> mbufs{};

    while (context.stop_requested == nullptr ||
           !context.stop_requested->load(std::memory_order_relaxed)) {
        const uint16_t nb_rx = rte_eth_rx_burst(context.port_id,
                                                context.queue_id,
                                                mbufs.data(),
                                                context.batch_size);
        if (nb_rx == 0) {
            continue;
        }

        uint64_t bytes = 0;
        for (uint16_t i = 0; i < nb_rx; ++i) {
            bytes += rte_pktmbuf_pkt_len(mbufs[i]);
        }

        context.stats.rx_received += nb_rx;
        context.stats.rx_bytes += bytes;
        publish_rx_worker_stats(context);
        rte_pktmbuf_free_bulk(mbufs.data(), nb_rx);
    }

    return 0;
}

std::vector<unsigned> worker_lcores() {
    std::vector<unsigned> lcores;
    unsigned lcore_id = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        lcores.push_back(lcore_id);
    }
    return lcores;
}

Runtime::WorkerResult make_worker_result(const WorkerContext& context) {
    return Runtime::WorkerResult{
        context.worker_id,
        context.lcore_id,
        context.queue_id,
        context.first_flow,
        context.flow_count,
        context.stats.tx_attempted,
        context.stats.tx_sent,
        0,
        0,
    };
}

Runtime::WorkerResult make_rx_worker_result(const RxWorkerContext& context) {
    return Runtime::WorkerResult{
        context.worker_id,
        context.lcore_id,
        context.queue_id,
        0,
        0,
        0,
        0,
        context.stats.rx_received,
        context.stats.rx_bytes,
    };
}

bool transmit_on_main(uint16_t port_id,
                      rte_mempool& mbuf_pool,
                      const PacketGenerator& generator,
                      const GeneratedPacket& generated_packet,
                      uint16_t batch_size,
                      const Runtime::RunOptions& options,
                      Runtime::Result& result) {
    WorkerContext context;
    context.worker_id = 0;
    context.lcore_id = rte_lcore_id();
    context.port_id = port_id;
    context.queue_id = 0;
    const auto range = assigned_flow_range(generated_packet.flow_plan.planned_packets, 1, 0, options.split);
    context.first_flow = range.first;
    context.flow_count = range.count;
    context.clone_count = options.clone_count;
    context.once = options.once;
    context.split = options.split;
    context.stop_requested = &runtime_stop_requested;
    context.mbuf_pool = &mbuf_pool;
    context.generator = &generator;
    context.packet = &generated_packet;
    context.batch_size = batch_size;
    context.total_pmd_threads = 1;
    context.stats_interval_seconds = options.stats_interval_seconds;

    const auto rc = run_worker(&context);
    result.tx_attempted += context.stats.tx_attempted;
    result.tx_sent += context.stats.tx_sent;
    result.workers.push_back(make_worker_result(context));
    result.errors.insert(result.errors.end(), context.stats.errors.begin(), context.stats.errors.end());
    return rc == 0;
}

std::vector<WorkerStatsView> collect_worker_stats_views(std::span<const WorkerContext> contexts,
                                                        size_t count) {
    std::vector<WorkerStatsView> views;
    views.reserve(count);
    for (size_t index = 0; index < count; ++index) {
        views.push_back(make_worker_stats_view(contexts[index]));
    }
    return views;
}

std::vector<RxWorkerStatsView> collect_rx_worker_stats_views(std::span<const RxWorkerContext> contexts,
                                                             size_t count) {
    std::vector<RxWorkerStatsView> views;
    views.reserve(count);
    for (size_t index = 0; index < count; ++index) {
        views.push_back(make_rx_worker_stats_view(contexts[index]));
    }
    return views;
}

bool wait_for_workers(std::span<const unsigned> lcores,
                      size_t launched,
                      Runtime::Result& result) {
    bool ok = true;
    for (size_t worker = 0; worker < launched; ++worker) {
        const int rc = rte_eal_wait_lcore(lcores[worker]);
        if (rc != 0) {
            ok = false;
            result.errors.push_back(std::format("worker on lcore {} failed with code {}",
                                                lcores[worker],
                                                rc));
        }
    }
    return ok;
}

bool wait_for_workers_with_stats(std::span<const unsigned> lcores,
                                 size_t total_launched,
                                 std::span<const WorkerContext> tx_contexts,
                                 size_t tx_launched,
                                 std::span<const RxWorkerContext> rx_contexts,
                                 size_t rx_launched,
                                 uint16_t port_id,
                                 const GeneratedPacket& generated_packet,
                                 uint16_t batch_size,
                                 const Runtime::RunOptions& options,
                                 Runtime::Result& result) {
    if (!options.stats_interval_seconds) {
        return wait_for_workers(lcores, total_launched, result);
    }

    LiveStatsDisplay display{*options.stats_interval_seconds};
    std::vector<bool> joined(total_launched, false);
    size_t joined_count = 0;
    bool ok = true;

    while (joined_count < total_launched) {
        rte_eth_stats eth_stats{};
        const int stats_rc = rte_eth_stats_get(port_id, &eth_stats);
        const uint64_t imissed = stats_rc == 0 ? eth_stats.imissed : 0;
        const uint64_t ierrors = stats_rc == 0 ? eth_stats.ierrors : 0;

        auto tx_views = collect_worker_stats_views(tx_contexts, tx_launched);
        auto rx_views = collect_rx_worker_stats_views(rx_contexts, rx_launched);

        display.refresh_if_due(tx_views,
                               rx_views,
                               imissed,
                               ierrors,
                               generated_packet.packet_len,
                               tx_launched,
                               rx_launched,
                               batch_size,
                               options.clone_count,
                               options.split,
                               options.once);

        for (size_t worker = 0; worker < total_launched; ++worker) {
            if (joined[worker] || rte_eal_get_lcore_state(lcores[worker]) != WAIT) {
                continue;
            }
            const int rc = rte_eal_wait_lcore(lcores[worker]);
            joined[worker] = true;
            ++joined_count;
            if (rc != 0) {
                ok = false;
                result.errors.push_back(std::format("worker on lcore {} failed with code {}",
                                                    lcores[worker],
                                                    rc));
            }
        }

        if (joined_count < total_launched) {
            std::this_thread::sleep_for(std::chrono::milliseconds{25});
        }
    }
    return ok;
}

bool run_traffic(uint16_t port_id,
                 rte_mempool& mbuf_pool,
                 const PacketGenerator& generator,
                 const GeneratedPacket& generated_packet,
                 uint16_t batch_size,
                 uint64_t tx_threads,
                 uint64_t rx_threads,
                 const Runtime::RunOptions& options,
                 Runtime::Result& result) {
    auto lcores = worker_lcores();
    const auto total_threads = tx_threads + rx_threads;
    if (lcores.size() < total_threads) {
        result.errors.push_back(std::format("PMD_THREADS({}) + RX_THREADS({}) requires {} worker lcore(s), but DPDK_ARGS enabled {}; use DPDK_ARGS like \"-l 0-{}\"",
                                            tx_threads,
                                            rx_threads,
                                            total_threads,
                                            lcores.size(),
                                            total_threads));
        return false;
    }

    std::vector<WorkerContext> tx_contexts;
    std::vector<PublishedWorkerStats> tx_published_stats;
    tx_contexts.reserve(static_cast<size_t>(tx_threads));
    tx_published_stats.reserve(static_cast<size_t>(tx_threads));
    for (uint64_t i = 0; i < tx_threads; ++i) {
        tx_published_stats.emplace_back();
    }

    std::vector<RxWorkerContext> rx_contexts;
    std::vector<PublishedRxWorkerStats> rx_published_stats;
    rx_contexts.reserve(static_cast<size_t>(rx_threads));
    rx_published_stats.reserve(static_cast<size_t>(rx_threads));
    for (uint64_t i = 0; i < rx_threads; ++i) {
        rx_published_stats.emplace_back();
    }

    size_t total_launched = 0;
    bool ok = true;

    // Launch TX workers
    for (uint64_t worker = 0; worker < tx_threads; ++worker) {
        auto& context = tx_contexts.emplace_back();
        context.worker_id = worker;
        context.lcore_id = lcores[worker];
        context.port_id = port_id;
        context.queue_id = static_cast<uint16_t>(worker);
        const auto range = assigned_flow_range(generated_packet.flow_plan.planned_packets,
                                               tx_threads,
                                               worker,
                                               options.split);
        context.first_flow = range.first;
        context.flow_count = range.count;
        context.clone_count = options.clone_count;
        context.once = options.once;
        context.split = options.split;
        context.stop_requested = &runtime_stop_requested;
        context.mbuf_pool = &mbuf_pool;
        context.generator = &generator;
        context.packet = &generated_packet;
        context.batch_size = batch_size;
        context.total_pmd_threads = tx_threads;
        context.published_stats = &tx_published_stats[worker];
        publish_worker_stats(context);

        const int rc = rte_eal_remote_launch(run_worker, &context, lcores[worker]);
        if (rc < 0) {
            result.errors.push_back(std::format("rte_eal_remote_launch failed for TX lcore {}: {}",
                                                lcores[worker],
                                                rte_strerror(-rc)));
            ok = false;
            break;
        }
        ++total_launched;
    }

    const size_t tx_launched = total_launched;

    // Launch RX workers
    for (uint64_t worker = 0; worker < rx_threads; ++worker) {
        auto& context = rx_contexts.emplace_back();
        context.worker_id = worker;
        context.lcore_id = lcores[tx_threads + worker];
        context.port_id = port_id;
        context.queue_id = static_cast<uint16_t>(worker);
        context.stop_requested = &runtime_stop_requested;
        context.batch_size = runtime_rx_batch_size;
        context.published_stats = &rx_published_stats[worker];
        publish_rx_worker_stats(context);

        const int rc = rte_eal_remote_launch(run_rx_worker, &context, lcores[tx_threads + worker]);
        if (rc < 0) {
            result.errors.push_back(std::format("rte_eal_remote_launch failed for RX lcore {}: {}",
                                                lcores[tx_threads + worker],
                                                rte_strerror(-rc)));
            ok = false;
            break;
        }
        ++total_launched;
    }

    const size_t rx_launched = total_launched - tx_launched;

    ok = wait_for_workers_with_stats(std::span{lcores.data(), total_launched},
                                     total_launched,
                                     std::span{tx_contexts.data(), tx_launched},
                                     tx_launched,
                                     std::span{rx_contexts.data(), rx_launched},
                                     rx_launched,
                                     port_id,
                                     generated_packet,
                                     batch_size,
                                     options,
                                     result) && ok;

    for (const auto& context : tx_contexts) {
        result.tx_attempted += context.stats.tx_attempted;
        result.tx_sent += context.stats.tx_sent;
        result.workers.push_back(make_worker_result(context));
        result.errors.insert(result.errors.end(), context.stats.errors.begin(), context.stats.errors.end());
    }

    for (const auto& context : rx_contexts) {
        result.rx_received += context.stats.rx_received;
        result.rx_bytes += context.stats.rx_bytes;
        result.rx_workers.push_back(make_rx_worker_result(context));
    }

    return ok;
}

void stop_and_close_port(uint16_t port_id, Runtime::Result& result) {
    int rc = rte_eth_dev_stop(port_id);
    if (rc < 0) {
        result.warnings.push_back(std::format("rte_eth_dev_stop failed for port {}: {}",
                                              port_id,
                                              rte_strerror(-rc)));
    }
    rc = rte_eth_dev_close(port_id);
    if (rc < 0) {
        result.warnings.push_back(std::format("rte_eth_dev_close failed for port {}: {}",
                                              port_id,
                                              rte_strerror(-rc)));
    }
}

void cleanup_eal(Runtime::Result& result) {
    int rc = rte_eal_cleanup();
    if (rc < 0) {
        result.warnings.push_back(std::format("rte_eal_cleanup failed: {}", rte_strerror(rte_errno)));
    }
}

} // namespace

Runtime::Runtime() = default;

Runtime::Runtime(Registry registry)
    : registry_(std::move(registry))
{
}

std::optional<std::vector<std::string>> Runtime::split_dpdk_args(std::string_view args,
                                                                 std::string& error) {
    std::vector<std::string> result;
    std::string current;
    char quote = '\0';
    bool escaping = false;

    for (char c : args) {
        if (escaping) {
            current.push_back(c);
            escaping = false;
            continue;
        }

        if (c == '\\') {
            escaping = true;
            continue;
        }

        if (quote != '\0') {
            if (c == quote) {
                quote = '\0';
            } else {
                current.push_back(c);
            }
            continue;
        }

        if (c == '\'' || c == '"') {
            quote = c;
            continue;
        }

        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            if (!current.empty()) {
                result.push_back(std::move(current));
                current.clear();
            }
            continue;
        }

        current.push_back(c);
    }

    if (escaping) {
        error = "DPDK_ARGS ends with an unfinished escape";
        return std::nullopt;
    }
    if (quote != '\0') {
        error = "DPDK_ARGS contains an unterminated quote";
        return std::nullopt;
    }
    if (!current.empty()) {
        result.push_back(std::move(current));
    }

    return result;
}

std::optional<Runtime::Config> Runtime::build_config(const Program& program, Result& result, const RunOptions& options /*= RunOptions{}*/) {
    std::unordered_map<std::string_view, const Variable*> variables;

    for (const auto& variable : program.variables) {
        if (variables.contains(variable.name)) {
            result.errors.push_back(std::format("duplicate variable '{}'", variable.name));
            continue;
        }
        variables.emplace(variable.name, &variable);
    }

    auto packet_it = variables.find("PACKET");
    if (packet_it == variables.end() && !options.capture) {
        result.errors.emplace_back("missing mandatory variable 'PACKET'");
    }

    auto dpdk_args_it = variables.find("DPDK_ARGS");
    if (dpdk_args_it == variables.end()) {
        result.errors.emplace_back("missing mandatory variable 'DPDK_ARGS'");
    }

    if (!result.errors.empty()) {
        return std::nullopt;
    }

    Config config;

    if (packet_it != variables.end()) {
        auto packet_value = evaluate(packet_it->second->expression);
        if (!std::holds_alternative<Packet>(packet_value)) {
            result.errors.emplace_back("variable 'PACKET' must be a packet expression");
        } else {
            config.packet = std::get<Packet>(std::move(packet_value));
        }
    }

    auto dpdk_args_value = evaluate(dpdk_args_it->second->expression);
    if (!std::holds_alternative<std::string>(dpdk_args_value)) {
        result.errors.emplace_back("variable 'DPDK_ARGS' must be a string expression");
    } else {
        std::string split_error;
        auto args = split_dpdk_args(std::get<std::string>(dpdk_args_value), split_error);
        if (!args) {
            result.errors.push_back(std::move(split_error));
        } else {
            config.dpdk_args = std::move(*args);
        }
    }

    auto packet_count_it = variables.find("PACKET_COUNT");
    if (packet_count_it != variables.end()) {
        auto packet_count_value = evaluate(packet_count_it->second->expression);
        if (!std::holds_alternative<int64_t>(packet_count_value)) {
            result.errors.emplace_back("variable 'PACKET_COUNT' must be an integer expression");
        } else {
            const auto packet_count = std::get<int64_t>(packet_count_value);
            if (packet_count <= 0) {
                result.errors.emplace_back("variable 'PACKET_COUNT' must be positive");
            } else {
                config.packet_count = static_cast<uint64_t>(packet_count);
            }
        }
    }

    auto pmd_threads_it = variables.find("PMD_THREADS");
    if (pmd_threads_it != variables.end()) {
        auto pmd_threads_value = evaluate(pmd_threads_it->second->expression);
        if (!std::holds_alternative<int64_t>(pmd_threads_value)) {
            result.errors.emplace_back("variable 'PMD_THREADS' must be an integer expression");
        } else {
            const auto pmd_threads = std::get<int64_t>(pmd_threads_value);
            if (pmd_threads <= 0) {
                result.errors.emplace_back("variable 'PMD_THREADS' must be positive");
            } else if (pmd_threads > std::numeric_limits<uint16_t>::max()) {
                result.errors.emplace_back("variable 'PMD_THREADS' exceeds the supported Tx queue count");
            } else {
                config.pmd_threads = static_cast<uint64_t>(pmd_threads);
            }
        }
    }

    auto rx_threads_it = variables.find("RX_THREADS");
    if (rx_threads_it != variables.end()) {
        auto rx_threads_value = evaluate(rx_threads_it->second->expression);
        if (!std::holds_alternative<int64_t>(rx_threads_value)) {
            result.errors.emplace_back("variable 'RX_THREADS' must be an integer expression");
        } else {
            const auto rx_threads = std::get<int64_t>(rx_threads_value);
            if (rx_threads <= 0) {
                result.errors.emplace_back("variable 'RX_THREADS' must be positive");
            } else if (rx_threads > std::numeric_limits<uint16_t>::max()) {
                result.errors.emplace_back("variable 'RX_THREADS' exceeds the supported Rx queue count");
            } else {
                config.rx_threads = static_cast<uint64_t>(rx_threads);
            }
        }
    }

    auto tx_batch_size_it = variables.find("TX_BATCH_SIZE");
    if (tx_batch_size_it != variables.end()) {
        auto tx_batch_size_value = evaluate(tx_batch_size_it->second->expression);
        if (!std::holds_alternative<int64_t>(tx_batch_size_value)) {
            result.errors.emplace_back("variable 'TX_BATCH_SIZE' must be an integer expression");
        } else {
            const auto tx_batch_size = std::get<int64_t>(tx_batch_size_value);
            if (tx_batch_size <= 0) {
                result.errors.emplace_back("variable 'TX_BATCH_SIZE' must be positive");
            } else if (tx_batch_size > runtime_max_tx_batch_size) {
                result.errors.push_back(std::format("variable 'TX_BATCH_SIZE' must be <= {}",
                                                    runtime_max_tx_batch_size));
            } else {
                config.tx_batch_size = static_cast<uint64_t>(tx_batch_size);
            }
        }
    }

    for (const auto& variable : program.variables) {
        if (variable.name != "PACKET" && variable.name != "DPDK_ARGS" &&
            variable.name != "PACKET_COUNT" && variable.name != "PMD_THREADS" &&
            variable.name != "RX_THREADS" && variable.name != "TX_BATCH_SIZE") {
            result.warnings.push_back(std::format("unknown runtime variable '{}'", variable.name));
        }
    }

    if (!result.errors.empty()) {
        return std::nullopt;
    }
    return config;
}

std::optional<Runtime::Config> Runtime::checked_config(const Program& program, Result& result, const RunOptions& options /*= RunOptions{}*/) const {
    auto config = build_config(program, result, options);
    if (!config) {
        return std::nullopt;
    }

    Checker checker{registry_};
    auto check = checker.check(config->packet);
    result.warnings.insert(result.warnings.end(), check.warnings.begin(), check.warnings.end());
    result.errors.insert(result.errors.end(), check.errors.begin(), check.errors.end());
    if (!check.ok) {
        return std::nullopt;
    }

    result.ok = true;
    return config;
}

Runtime::Result Runtime::check(const Program& program) const {
    return check(program, RunOptions{});
}

Runtime::Result Runtime::check(const Program& program, RunOptions options) const {
    Result result;
    auto config = build_config(program, result, options);
    if (!config) {
        return result;
    }

    if (options.capture) {
        result.pmd_threads = config->pmd_threads.value_or(1);
        result.rx_threads = config->rx_threads.value_or(0);
        result.tx_batch_size = config->tx_batch_size;
        result.ok = true;
        return result;
    }

    PacketGenerator generator{registry_};
    auto generated = generator.prepare(config->packet, config->packet_count, live_fixup_options());
    result.warnings.insert(result.warnings.end(), generated.warnings.begin(), generated.warnings.end());
    result.errors.insert(result.errors.end(), generated.errors.begin(), generated.errors.end());
    if (!generated.ok || !generated.packet) {
        return result;
    }

    result.packet_len = generated.packet->packet_len;
    result.total_flows = generated.packet->flow_plan.total_flows;
    result.planned_packets = generated.packet->flow_plan.planned_packets;
    result.pmd_threads = config->pmd_threads.value_or(1);
    result.rx_threads = config->rx_threads.value_or(0);
    result.tx_batch_size = config->tx_batch_size;
    result.clone_count = options.clone_count;
    result.stats_interval_seconds = options.stats_interval_seconds;
    result.split = options.split;
    result.once = options.once;
    result.planned_transmissions = checked_total_transmission_count(result.planned_packets,
                                                                    result.pmd_threads,
                                                                    options,
                                                                    result);
    if (!result.errors.empty()) {
        return result;
    }
    result.ok = true;
    return result;
}

Runtime::Result Runtime::init(const Program& program, std::string_view eal_program_name) {
    Result result;
    auto config = checked_config(program, result, RunOptions{});
    if (!config) {
        return result;
    }

    if (init_eal(std::move(config->dpdk_args), eal_program_name, result) < 0) {
        result.ok = false;
        return result;
    }

    result.ok = true;
    return result;
}

Runtime::Result Runtime::run(const Program& program, std::string_view eal_program_name) {
    return run(program, eal_program_name, RunOptions{});
}

Runtime::Result Runtime::run(const Program& program,
                             std::string_view eal_program_name,
                             RunOptions options) {
    Result result;
    auto config = build_config(program, result, options);
    if (!config) {
        return result;
    }

    if (options.capture) {
        result.pmd_threads = config->pmd_threads.value_or(1);
        result.rx_threads = config->rx_threads.value_or(0);
        result.tx_batch_size = config->tx_batch_size;

        if (!check_tap_permission(result)) {
            result.ok = false;
            return result;
        }

        if (init_eal(std::move(config->dpdk_args), eal_program_name, result) < 0) {
            result.ok = false;
            return result;
        }

        const auto rx_threads = config->rx_threads.value_or(0);
        const auto total_threads = rx_threads;

        if (total_threads > 1) {
            const auto lcores = worker_lcores();
            if (lcores.size() < total_threads) {
                result.errors.push_back(std::format("RX_THREADS({}) requires {} worker lcore(s), but DPDK_ARGS enabled {}; use DPDK_ARGS like \"-l 0-{}\"",
                                                    rx_threads,
                                                    total_threads,
                                                    lcores.size(),
                                                    total_threads));
                cleanup_eal(result);
                result.ok = false;
                return result;
            }
        }

        bool port_started = false;
        const auto tx_queue_count = uint16_t{1};
        const auto rx_queue_count = rx_threads > 0 ? static_cast<uint16_t>(rx_threads) : uint16_t{1};
        SignalGuard signal_guard;

        rte_mempool* pool = rte_pktmbuf_pool_create("packet_capture_mbuf_pool",
                                                     8191,
                                                     runtime_mbuf_cache_size,
                                                     0,
                                                     RTE_MBUF_DEFAULT_BUF_SIZE,
                                                     rte_socket_id());
        if (pool == nullptr) {
            result.errors.push_back(std::format("rte_pktmbuf_pool_create failed: {}", rte_strerror(rte_errno)));
            cleanup_eal(result);
            result.ok = false;
            return result;
        }

        std::optional<PcapWriter> pcap_writer;
        std::optional<std::ofstream> capture_stream;
        if (options.capture_file) {
            capture_stream.emplace(*options.capture_file, std::ios::binary);
            if (!capture_stream->is_open()) {
                result.errors.push_back(std::format("failed to open capture file '{}'", *options.capture_file));
                rte_mempool_free(pool);
                cleanup_eal(result);
                result.ok = false;
                return result;
            }
            pcap_writer.emplace(*capture_stream);
            auto write_result = pcap_writer->write_header();
            if (!write_result.ok) {
                result.errors.insert(result.errors.end(), write_result.errors.begin(), write_result.errors.end());
                rte_mempool_free(pool);
                cleanup_eal(result);
                result.ok = false;
                return result;
            }
        }

        if (probe_tap_port(result) &&
            configure_and_start_port(runtime_port_id, rx_queue_count, tx_queue_count, *pool, result)) {
            port_started = true;

            if (options.capture_file) {
                // Main-thread RX loop with pcap writing
                std::array<rte_mbuf*, runtime_max_rx_batch_size> mbufs{};
                while (!runtime_stop_requested.load(std::memory_order_relaxed)) {
                    const uint16_t nb_rx = rte_eth_rx_burst(runtime_port_id,
                                                            0,
                                                            mbufs.data(),
                                                            runtime_rx_batch_size);
                    if (nb_rx == 0) {
                        continue;
                    }

                    uint64_t bytes = 0;
                    for (uint16_t i = 0; i < nb_rx; ++i) {
                        auto* data = rte_pktmbuf_mtod(mbufs[i], const std::byte*);
                        auto len = rte_pktmbuf_pkt_len(mbufs[i]);
                        std::span<const std::byte> payload(data, len);
                        auto write_result = pcap_writer->write_packet(payload);
                        if (!write_result.ok) {
                            result.errors.insert(result.errors.end(), write_result.errors.begin(), write_result.errors.end());
                            break;
                        }
                        bytes += len;
                    }

                    result.rx_received += nb_rx;
                    result.rx_bytes += bytes;
                    rte_pktmbuf_free_bulk(mbufs.data(), nb_rx);

                    if (!result.errors.empty()) {
                        break;
                    }
                }
            } else {
                // Stats-only capture: launch remote RX workers if configured
                if (total_threads > 1) {
                    std::vector<RxWorkerContext> rx_contexts;
                    std::vector<PublishedRxWorkerStats> rx_published_stats;
                    rx_contexts.reserve(static_cast<size_t>(rx_threads));
                    rx_published_stats.reserve(static_cast<size_t>(rx_threads));
                    for (uint64_t i = 0; i < rx_threads; ++i) {
                        rx_published_stats.emplace_back();
                    }

                    auto lcores = worker_lcores();
                    size_t launched = 0;
                    bool ok = true;

                    for (uint64_t worker = 0; worker < rx_threads; ++worker) {
                        auto& context = rx_contexts.emplace_back();
                        context.worker_id = worker;
                        context.lcore_id = lcores[worker];
                        context.port_id = runtime_port_id;
                        context.queue_id = static_cast<uint16_t>(worker);
                        context.stop_requested = &runtime_stop_requested;
                        context.batch_size = runtime_rx_batch_size;
                        context.published_stats = &rx_published_stats[worker];
                        publish_rx_worker_stats(context);

                        const int rc = rte_eal_remote_launch(run_rx_worker, &context, lcores[worker]);
                        if (rc < 0) {
                            result.errors.push_back(std::format("rte_eal_remote_launch failed for RX lcore {}: {}",
                                                                lcores[worker],
                                                                rte_strerror(-rc)));
                            ok = false;
                            break;
                        }
                        ++launched;
                    }

                    if (ok) {
                        // Wait for signal, then workers finish
                        for (size_t worker = 0; worker < launched; ++worker) {
                            rte_eal_wait_lcore(lcores[worker]);
                        }
                    } else {
                        // Workers may still be running; signal stop and wait
                        runtime_stop_requested.store(true, std::memory_order_relaxed);
                        for (size_t worker = 0; worker < launched; ++worker) {
                            rte_eal_wait_lcore(lcores[worker]);
                        }
                    }

                    for (const auto& context : rx_contexts) {
                        result.rx_received += context.stats.rx_received;
                        result.rx_bytes += context.stats.rx_bytes;
                        result.rx_workers.push_back(make_rx_worker_result(context));
                    }
                } else {
                    // Single RX worker on main thread
                    RxWorkerContext context{};
                    context.worker_id = 0;
                    context.lcore_id = rte_lcore_id();
                    context.port_id = runtime_port_id;
                    context.queue_id = 0;
                    context.stop_requested = &runtime_stop_requested;
                    context.batch_size = runtime_rx_batch_size;
                    run_rx_worker(&context);
                    result.rx_received += context.stats.rx_received;
                    result.rx_bytes += context.stats.rx_bytes;
                    result.rx_workers.push_back(make_rx_worker_result(context));
                }
            }
        }

        if (port_started) {
            rte_eth_stats eth_stats{};
            if (rte_eth_stats_get(runtime_port_id, &eth_stats) == 0) {
                result.rx_missed = eth_stats.imissed;
                result.rx_errors = eth_stats.ierrors;
            }
            stop_and_close_port(runtime_port_id, result);
        }

        pcap_writer.reset();
        capture_stream.reset();
        rte_mempool_free(pool);
        cleanup_eal(result);

        result.ok = result.errors.empty();
        return result;
    }

    PacketGenerator generator{registry_};
    auto generated = generator.prepare(config->packet, config->packet_count, live_fixup_options());
    result.warnings.insert(result.warnings.end(), generated.warnings.begin(), generated.warnings.end());
    result.errors.insert(result.errors.end(), generated.errors.begin(), generated.errors.end());
    if (!generated.ok || !generated.packet) {
        return result;
    }
    result.packet_len = generated.packet->packet_len;
    result.total_flows = generated.packet->flow_plan.total_flows;
    result.planned_packets = generated.packet->flow_plan.planned_packets;
    result.pmd_threads = config->pmd_threads.value_or(1);
    result.rx_threads = config->rx_threads.value_or(0);
    result.tx_batch_size = config->tx_batch_size;
    result.clone_count = options.clone_count;
    result.stats_interval_seconds = options.stats_interval_seconds;
    result.split = options.split;
    result.once = options.once;

    result.planned_transmissions = checked_total_transmission_count(result.planned_packets,
                                                                    result.pmd_threads,
                                                                    options,
                                                                    result);
    if (!result.errors.empty()) {
        return result;
    }

    if (!check_tap_permission(result)) {
        result.ok = false;
        return result;
    }

    if (init_eal(std::move(config->dpdk_args), eal_program_name, result) < 0) {
        result.ok = false;
        return result;
    }

    const auto tx_threads = config->pmd_threads.value_or(1);
    const auto rx_threads = config->rx_threads.value_or(0);
    const auto total_threads = tx_threads + rx_threads;

    if (total_threads > 1) {
        const auto lcores = worker_lcores();
        if (lcores.size() < total_threads) {
            result.errors.push_back(std::format("PMD_THREADS({}) + RX_THREADS({}) requires {} worker lcore(s), but DPDK_ARGS enabled {}; use DPDK_ARGS like \"-l 0-{}\"",
                                                tx_threads,
                                                rx_threads,
                                                total_threads,
                                                lcores.size(),
                                                total_threads));
            cleanup_eal(result);
            result.ok = false;
            return result;
        }
    }

    bool port_started = false;
    const auto tx_queue_count = static_cast<uint16_t>(tx_threads);
    const auto rx_queue_count = rx_threads > 0 ? static_cast<uint16_t>(rx_threads) : tx_queue_count;
    const auto batch_size = static_cast<uint16_t>(config->tx_batch_size);
    SignalGuard signal_guard;
    auto mbuf_pool = make_mbuf_pool(*generated.packet, tx_threads, batch_size, result);
    if (mbuf_pool != nullptr &&
        probe_tap_port(result) &&
        configure_and_start_port(runtime_port_id, rx_queue_count, tx_queue_count, *mbuf_pool, result)) {
        port_started = true;
        if (total_threads > 1) {
            run_traffic(runtime_port_id,
                        *mbuf_pool,
                        generator,
                        *generated.packet,
                        batch_size,
                        tx_threads,
                        rx_threads,
                        options,
                        result);
        } else {
            transmit_on_main(runtime_port_id,
                             *mbuf_pool,
                             generator,
                             *generated.packet,
                             batch_size,
                             options,
                             result);
        }
    }

    if (port_started) {
        rte_eth_stats eth_stats{};
        if (rte_eth_stats_get(runtime_port_id, &eth_stats) == 0) {
            result.rx_missed = eth_stats.imissed;
            result.rx_errors = eth_stats.ierrors;
        }
        stop_and_close_port(runtime_port_id, result);
    }

    mbuf_pool.reset();
    cleanup_eal(result);

    result.ok = result.errors.empty();
    return result;
}

} // namespace packet
