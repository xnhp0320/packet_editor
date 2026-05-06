#pragma once

#include "packet/ast.hpp"
#include "packet/checker.hpp"
#include "packet/registry.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace packet {

class Runtime {
public:
    struct Result {
        bool ok = false;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
        int eal_parsed_args = 0;
    };

    Runtime();
    explicit Runtime(Registry registry);

    Result check(const Program& program) const;
    Result init(const Program& program, std::string_view eal_program_name = "packet_editor");

private:
    struct Config {
        Packet packet;
        std::vector<std::string> dpdk_args;
    };

    static std::optional<Config> build_config(const Program& program, Result& result);
    std::optional<Config> checked_config(const Program& program, Result& result) const;
    static std::optional<std::vector<std::string>> split_dpdk_args(std::string_view args,
                                                                   std::string& error);

    Registry registry_;
};

} // namespace packet
