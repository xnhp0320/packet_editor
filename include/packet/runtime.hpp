#pragma once

#include "packet/ast.hpp"
#include "packet/checker.hpp"
#include "packet/registry.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace packet {

class Runtime {
public:
    struct WorkerResult {
        uint64_t worker_id = 0;
        uint64_t lcore_id = 0;
        uint16_t queue_id = 0;
        uint64_t first_flow = 0;
        uint64_t flow_count = 0;
        uint64_t tx_attempted = 0;
        uint64_t tx_sent = 0;
    };

    struct RunOptions {
        uint64_t clone_count = 1;
        bool split = false;
        bool once = false;
    };

    struct Result {
        bool ok = false;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
        int eal_parsed_args = 0;
        uint16_t port_id = 0;
        size_t packet_len = 0;
        uint64_t total_flows = 0;
        uint64_t planned_packets = 0;
        uint64_t planned_transmissions = 0;
        uint64_t tx_attempted = 0;
        uint64_t tx_sent = 0;
        uint64_t pmd_threads = 0;
        uint64_t tx_batch_size = 0;
        uint64_t clone_count = 1;
        bool split = false;
        bool once = false;
        std::vector<WorkerResult> workers;
    };

    Runtime();
    explicit Runtime(Registry registry);

    Result check(const Program& program) const;
    Result check(const Program& program, RunOptions options) const;
    Result init(const Program& program, std::string_view eal_program_name = "ffg");
    Result run(const Program& program, std::string_view eal_program_name = "ffg");
    Result run(const Program& program, std::string_view eal_program_name, RunOptions options);

private:
    struct Config {
        Packet packet;
        std::vector<std::string> dpdk_args;
        std::optional<uint64_t> packet_count;
        std::optional<uint64_t> pmd_threads;
        uint64_t tx_batch_size = 32;
    };

    static std::optional<Config> build_config(const Program& program, Result& result);
    std::optional<Config> checked_config(const Program& program, Result& result) const;
    static std::optional<std::vector<std::string>> split_dpdk_args(std::string_view args,
                                                                   std::string& error);

    Registry registry_;
};

} // namespace packet
