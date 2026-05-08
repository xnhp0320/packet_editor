#include "packet/runtime.hpp"

#include "packet/packet_constructor.hpp"
#include "packet/packet_serializer.hpp"

#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <format>
#include <memory>
#include <limits>
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
constexpr unsigned runtime_mbuf_count = 8191;
constexpr unsigned runtime_mbuf_cache_size = 250;
constexpr size_t runtime_max_packet_size = 2048;
constexpr std::string_view runtime_tap_name = "net_tap0";
constexpr std::string_view runtime_tap_args = "iface=packet_tap0,mac=fixed";
constexpr std::string_view runtime_tap_iface = "packet_tap0";

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

struct RuntimePacket {
    std::vector<std::byte> base_payload;
    std::vector<PayloadFieldModifier> modifiers;
};

struct FlowIndexPlan {
    uint64_t total_flows = 1;
    uint64_t planned_packets = 1;
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

MempoolPtr make_mbuf_pool(Runtime::Result& result) {
    rte_mempool* pool = rte_pktmbuf_pool_create("packet_runtime_mbuf_pool",
                                                runtime_mbuf_count,
                                                runtime_mbuf_cache_size,
                                                0,
                                                RTE_MBUF_DEFAULT_BUF_SIZE,
                                                rte_socket_id());
    if (pool == nullptr) {
        result.errors.push_back(std::format("rte_pktmbuf_pool_create failed: {}",
                                            rte_strerror(rte_errno)));
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

bool configure_and_start_port(uint16_t port_id, rte_mempool& mbuf_pool, Runtime::Result& result) {
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
    int rc = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (rc < 0) {
        result.errors.push_back(std::format("rte_eth_dev_configure failed for port {}: {}",
                                            port_id,
                                            rte_strerror(-rc)));
        return false;
    }

    rc = rte_eth_rx_queue_setup(port_id,
                                runtime_queue_id,
                                runtime_rx_descriptors,
                                rte_eth_dev_socket_id(port_id),
                                nullptr,
                                &mbuf_pool);
    if (rc < 0) {
        result.errors.push_back(std::format("rte_eth_rx_queue_setup failed for port {} queue {}: {}",
                                            port_id,
                                            runtime_queue_id,
                                            rte_strerror(-rc)));
        return false;
    }

    rc = rte_eth_tx_queue_setup(port_id,
                                runtime_queue_id,
                                runtime_tx_descriptors,
                                rte_eth_dev_socket_id(port_id),
                                nullptr);
    if (rc < 0) {
        result.errors.push_back(std::format("rte_eth_tx_queue_setup failed for port {} queue {}: {}",
                                            port_id,
                                            runtime_queue_id,
                                            rte_strerror(-rc)));
        return false;
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

std::optional<PacketConstructor> build_packet_constructor(const Packet& packet,
                                                          const Registry& registry,
                                                          Runtime::Result& result) {
    PacketConstructorBuilder builder{registry};
    auto constructor = builder.build(packet);
    result.warnings.insert(result.warnings.end(), constructor.warnings.begin(), constructor.warnings.end());
    result.errors.insert(result.errors.end(), constructor.errors.begin(), constructor.errors.end());
    if (!constructor.ok || !constructor.packet) {
        return std::nullopt;
    }
    return std::move(*constructor.packet);
}

std::optional<RuntimePacket> serialize_runtime_packet(const PacketConstructor& packet,
                                                      const Registry& registry,
                                                      Runtime::Result& result) {
    std::vector<std::byte> payload(runtime_max_packet_size);
    auto serialized = serialize_packet(packet, registry, PacketBufferView{payload});
    result.errors.insert(result.errors.end(), serialized.errors.begin(), serialized.errors.end());
    if (!serialized.ok) {
        return std::nullopt;
    }

    auto fixed = fixup_packet(packet, registry, PacketBufferView{payload}, serialized.packet_len);
    result.errors.insert(result.errors.end(), fixed.errors.begin(), fixed.errors.end());
    if (!fixed.ok) {
        return std::nullopt;
    }

    payload.resize(serialized.packet_len);
    result.packet_len = serialized.packet_len;
    return RuntimePacket{
        std::move(payload),
        std::move(serialized.modifiers),
    };
}

std::optional<FlowIndexPlan> plan_flow_indexes(const std::vector<PayloadFieldModifier>& modifiers,
                                               std::optional<uint64_t> packet_count,
                                               Runtime::Result& result) {
    FlowIndexPlan plan;
    for (const auto& modifier : modifiers) {
        if (modifier.value_count == 0) {
            result.errors.push_back(std::format("modifier '{}.{}' has zero values",
                                                modifier.protocol,
                                                modifier.field));
            return std::nullopt;
        }
        if (plan.total_flows > std::numeric_limits<uint64_t>::max() / modifier.value_count) {
            result.errors.push_back("range expansion has more than 18446744073709551615 flows");
            return std::nullopt;
        }
        plan.total_flows *= modifier.value_count;
    }

    plan.planned_packets = packet_count ? std::min(plan.total_flows, *packet_count)
                                        : plan.total_flows;
    result.total_flows = plan.total_flows;
    result.planned_packets = plan.planned_packets;
    return plan;
}

bool apply_flow_index(std::span<std::byte> payload,
                      const std::vector<PayloadFieldModifier>& modifiers,
                      uint64_t flow_index,
                      Runtime::Result& result) {
    uint64_t divisor = 1;
    for (const auto& modifier : modifiers) {
        const auto value_index = (flow_index / divisor) % modifier.value_count;
        std::string error;
        if (!modifier.apply(payload, value_index, error)) {
            result.errors.push_back(std::move(error));
            return false;
        }
        divisor *= modifier.value_count;
    }
    return true;
}

bool transmit_packet(uint16_t port_id,
                     rte_mempool& mbuf_pool,
                     std::span<const std::byte> payload,
                     Runtime::Result& result) {
    rte_mbuf* mbuf = rte_pktmbuf_alloc(&mbuf_pool);
    if (mbuf == nullptr) {
        result.errors.push_back(std::format("rte_pktmbuf_alloc failed: {}", rte_strerror(rte_errno)));
        return false;
    }

    void* packet_data = rte_pktmbuf_append(mbuf, static_cast<uint16_t>(payload.size()));
    if (packet_data == nullptr) {
        rte_pktmbuf_free(mbuf);
        result.errors.push_back(std::format("packet length {} does not fit in an mbuf", payload.size()));
        return false;
    }

    std::memcpy(packet_data, payload.data(), payload.size());

    rte_mbuf* packets[] = {mbuf};
    ++result.tx_attempted;
    const uint16_t sent = rte_eth_tx_burst(port_id, runtime_queue_id, packets, 1);
    result.tx_sent += sent;
    if (sent != 1) {
        rte_pktmbuf_free(mbuf);
        result.errors.push_back("rte_eth_tx_burst sent 0 of 1 packet(s)");
        return false;
    }

    return true;
}

bool transmit_planned_packets(uint16_t port_id,
                              rte_mempool& mbuf_pool,
                              const PacketConstructor& packet,
                              const Registry& registry,
                              const RuntimePacket& runtime_packet,
                              const FlowIndexPlan& plan,
                              Runtime::Result& result) {
    for (uint64_t flow_index = 0; flow_index < plan.planned_packets; ++flow_index) {
        auto payload = runtime_packet.base_payload;
        if (!apply_flow_index(payload, runtime_packet.modifiers, flow_index, result)) {
            return false;
        }

        auto fixed = fixup_packet(packet, registry, PacketBufferView{payload}, result.packet_len);
        result.errors.insert(result.errors.end(), fixed.errors.begin(), fixed.errors.end());
        if (!fixed.ok) {
            return false;
        }

        if (!transmit_packet(port_id, mbuf_pool, payload, result)) {
            return false;
        }
    }
    return true;
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

    for (const auto& variable : program.variables) {
        if (variable.name != "PACKET" && variable.name != "DPDK_ARGS" &&
            variable.name != "PACKET_COUNT") {
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
    Result result;
    auto config = checked_config(program, result);
    if (!config) {
        return result;
    }

    auto packet = build_packet_constructor(config->packet, registry_, result);
    if (!packet) {
        result.ok = false;
        return result;
    }

    auto runtime_packet = serialize_runtime_packet(*packet, registry_, result);
    if (!runtime_packet) {
        result.ok = false;
        return result;
    }

    if (!plan_flow_indexes(runtime_packet->modifiers, config->packet_count, result)) {
        result.ok = false;
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
    Result result;
    auto config = checked_config(program, result);
    if (!config) {
        return result;
    }

    auto packet = build_packet_constructor(config->packet, registry_, result);
    if (!packet) {
        result.ok = false;
        return result;
    }

    auto runtime_packet = serialize_runtime_packet(*packet, registry_, result);
    if (!runtime_packet) {
        result.ok = false;
        return result;
    }

    auto flow_plan = plan_flow_indexes(runtime_packet->modifiers, config->packet_count, result);
    if (!flow_plan) {
        result.ok = false;
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

    bool port_started = false;
    auto mbuf_pool = make_mbuf_pool(result);
    if (mbuf_pool != nullptr &&
        probe_tap_port(result) &&
        configure_and_start_port(runtime_port_id, *mbuf_pool, result)) {
        port_started = true;
        transmit_planned_packets(runtime_port_id,
                                 *mbuf_pool,
                                 *packet,
                                 registry_,
                                 *runtime_packet,
                                 *flow_plan,
                                 result);
    }

    if (port_started) {
        stop_and_close_port(runtime_port_id, result);
    }
    cleanup_eal(result);

    result.ok = result.errors.empty();
    return result;
}

} // namespace packet
