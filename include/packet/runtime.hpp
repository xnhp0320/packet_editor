#pragma once

#include "packet/ast.hpp"

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

    Result check(const Program& program) const;
    Result init(const Program& program, std::string_view eal_program_name = "packet_editor");

private:
    struct Config {
        Packet packet;
        std::vector<std::string> dpdk_args;
    };

    static std::optional<Config> build_config(const Program& program, Result& result);
    static std::optional<Config> checked_config(const Program& program, Result& result);
    static std::optional<std::vector<std::string>> split_dpdk_args(std::string_view args,
                                                                   std::string& error);
};

} // namespace packet
