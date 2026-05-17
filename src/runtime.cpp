#include "packet/runtime.hpp"

#include "packet/packet_generator.hpp"

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
#include <csignal>
#include <cstring>
#include <format>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
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
constexpr std::string_view runtime_tap_name = "net_tap0";
constexpr std::string_view runtime_tap_args = "iface=packet_tap0,mac=fixed";
constexpr std::string_view runtime_tap_iface = "packet_tap0";

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

struct WorkerContext {
    uint64_t worker_id = 0;
    uint64_t lcore_id = 0;
    uint16_t port_id = 0;
    uint16_t queue_id = 0;
    uint64_t first_flow = 0;
    uint64_t flow_count = 0;
    uint64_t clone_count = 1;
    bool once = false;
    const std::atomic_bool* stop_requested = nullptr;
    rte_mempool* mbuf_pool = nullptr;
    const PacketGenerator* generator = nullptr;
    const GeneratedPacket* packet = nullptr;
    uint16_t batch_size = runtime_default_tx_batch_size;
    WorkerStats stats;
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
                              uint16_t queue_count,
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
    int rc = rte_eth_dev_configure(port_id, queue_count, queue_count, &port_conf);
    if (rc < 0) {
        result.errors.push_back(std::format("rte_eth_dev_configure failed for port {}: {}",
                                            port_id,
                                            rte_strerror(-rc)));
        return false;
    }

    for (uint16_t queue_id = 0; queue_id < queue_count; ++queue_id) {
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

    for (uint16_t queue_id = 0; queue_id < queue_count; ++queue_id) {
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
    return context.generator->apply_flow(*context.packet, flow_index, payload, context.stats.errors);
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
                return 1;
            }
            transmitted += count;
        }
    } while (!context.once &&
             (context.stop_requested == nullptr ||
              !context.stop_requested->load(std::memory_order_relaxed)));

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
    context.stop_requested = &runtime_stop_requested;
    context.mbuf_pool = &mbuf_pool;
    context.generator = &generator;
    context.packet = &generated_packet;
    context.batch_size = batch_size;

    const auto rc = run_worker(&context);
    result.tx_attempted += context.stats.tx_attempted;
    result.tx_sent += context.stats.tx_sent;
    result.workers.push_back(make_worker_result(context));
    result.errors.insert(result.errors.end(), context.stats.errors.begin(), context.stats.errors.end());
    return rc == 0;
}

bool transmit_on_workers(uint16_t port_id,
                         rte_mempool& mbuf_pool,
                         const PacketGenerator& generator,
                         const GeneratedPacket& generated_packet,
                         uint16_t batch_size,
                         uint64_t requested_workers,
                         const Runtime::RunOptions& options,
                         Runtime::Result& result) {
    auto lcores = worker_lcores();
    if (lcores.size() < requested_workers) {
        result.errors.push_back(std::format("PMD_THREADS requests {} worker lcore(s), but DPDK_ARGS enabled {}; use DPDK_ARGS like \"-l 0-{}\"",
                                            requested_workers,
                                            lcores.size(),
                                            requested_workers));
        return false;
    }

    std::vector<WorkerContext> contexts;
    contexts.reserve(static_cast<size_t>(requested_workers));
    uint64_t launched = 0;
    bool ok = true;
    for (uint64_t worker = 0; worker < requested_workers; ++worker) {
        auto& context = contexts.emplace_back();
        context.worker_id = worker;
        context.lcore_id = lcores[worker];
        context.port_id = port_id;
        context.queue_id = static_cast<uint16_t>(worker);
        const auto range = assigned_flow_range(generated_packet.flow_plan.planned_packets,
                                               requested_workers,
                                               worker,
                                               options.split);
        context.first_flow = range.first;
        context.flow_count = range.count;
        context.clone_count = options.clone_count;
        context.once = options.once;
        context.stop_requested = &runtime_stop_requested;
        context.mbuf_pool = &mbuf_pool;
        context.generator = &generator;
        context.packet = &generated_packet;
        context.batch_size = batch_size;

        const int rc = rte_eal_remote_launch(run_worker, &context, lcores[worker]);
        if (rc < 0) {
            result.errors.push_back(std::format("rte_eal_remote_launch failed for lcore {}: {}",
                                                lcores[worker],
                                                rte_strerror(-rc)));
            ok = false;
            break;
        }
        ++launched;
    }

    for (uint64_t worker = 0; worker < launched; ++worker) {
        const int rc = rte_eal_wait_lcore(lcores[worker]);
        if (rc != 0) {
            ok = false;
            result.errors.push_back(std::format("PMD worker on lcore {} failed with code {}",
                                                lcores[worker],
                                                rc));
        }
    }

    for (const auto& context : contexts) {
        result.tx_attempted += context.stats.tx_attempted;
        result.tx_sent += context.stats.tx_sent;
        result.workers.push_back(make_worker_result(context));
        result.errors.insert(result.errors.end(), context.stats.errors.begin(), context.stats.errors.end());
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

std::optional<Runtime::Config> Runtime::build_config(const Program& program, Result& result) {
    std::unordered_map<std::string_view, const Variable*> variables;

    for (const auto& variable : program.variables) {
        if (variables.contains(variable.name)) {
            result.errors.push_back(std::format("duplicate variable '{}'", variable.name));
            continue;
        }
        variables.emplace(variable.name, &variable);
    }

    auto packet_it = variables.find("PACKET");
    if (packet_it == variables.end()) {
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

    auto packet_value = evaluate(packet_it->second->expression);
    if (!std::holds_alternative<Packet>(packet_value)) {
        result.errors.emplace_back("variable 'PACKET' must be a packet expression");
    } else {
        config.packet = std::get<Packet>(std::move(packet_value));
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
            variable.name != "TX_BATCH_SIZE") {
            result.warnings.push_back(std::format("unknown runtime variable '{}'", variable.name));
        }
    }

    if (!result.errors.empty()) {
        return std::nullopt;
    }
    return config;
}

std::optional<Runtime::Config> Runtime::checked_config(const Program& program, Result& result) const {
    auto config = build_config(program, result);
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
    auto config = build_config(program, result);
    if (!config) {
        return result;
    }

    PacketGenerator generator{registry_};
    auto generated = generator.prepare(config->packet, config->packet_count);
    result.warnings.insert(result.warnings.end(), generated.warnings.begin(), generated.warnings.end());
    result.errors.insert(result.errors.end(), generated.errors.begin(), generated.errors.end());
    if (!generated.ok || !generated.packet) {
        return result;
    }

    result.packet_len = generated.packet->packet_len;
    result.total_flows = generated.packet->flow_plan.total_flows;
    result.planned_packets = generated.packet->flow_plan.planned_packets;
    result.pmd_threads = config->pmd_threads.value_or(1);
    result.tx_batch_size = config->tx_batch_size;
    result.clone_count = options.clone_count;
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
    auto config = checked_config(program, result);
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
    auto config = build_config(program, result);
    if (!config) {
        return result;
    }

    PacketGenerator generator{registry_};
    auto generated = generator.prepare(config->packet, config->packet_count);
    result.warnings.insert(result.warnings.end(), generated.warnings.begin(), generated.warnings.end());
    result.errors.insert(result.errors.end(), generated.errors.begin(), generated.errors.end());
    if (!generated.ok || !generated.packet) {
        return result;
    }
    result.packet_len = generated.packet->packet_len;
    result.total_flows = generated.packet->flow_plan.total_flows;
    result.planned_packets = generated.packet->flow_plan.planned_packets;
    result.pmd_threads = config->pmd_threads.value_or(1);
    result.tx_batch_size = config->tx_batch_size;
    result.clone_count = options.clone_count;
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

    if (config->pmd_threads) {
        const auto lcores = worker_lcores();
        if (lcores.size() < *config->pmd_threads) {
            result.errors.push_back(std::format("PMD_THREADS requests {} worker lcore(s), but DPDK_ARGS enabled {}; use DPDK_ARGS like \"-l 0-{}\"",
                                                *config->pmd_threads,
                                                lcores.size(),
                                                *config->pmd_threads));
            cleanup_eal(result);
            result.ok = false;
            return result;
        }
    }

    bool port_started = false;
    const auto worker_count = config->pmd_threads.value_or(1);
    const auto queue_count = static_cast<uint16_t>(worker_count);
    const auto batch_size = static_cast<uint16_t>(config->tx_batch_size);
    SignalGuard signal_guard;
    auto mbuf_pool = make_mbuf_pool(*generated.packet, worker_count, batch_size, result);
    if (mbuf_pool != nullptr &&
        probe_tap_port(result) &&
        configure_and_start_port(runtime_port_id, queue_count, *mbuf_pool, result)) {
        port_started = true;
        if (config->pmd_threads) {
            transmit_on_workers(runtime_port_id,
                                *mbuf_pool,
                                generator,
                                *generated.packet,
                                batch_size,
                                *config->pmd_threads,
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
        stop_and_close_port(runtime_port_id, result);
    }

    mbuf_pool.reset();
    cleanup_eal(result);

    result.ok = result.errors.empty();
    return result;
}

} // namespace packet
