#include "packet/runtime.hpp"

#include "packet/checker.hpp"

#include <rte_eal.h>
#include <rte_errno.h>

#include <format>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace packet {

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

    for (const auto& variable : program.variables) {
        if (variable.name != "PACKET" && variable.name != "DPDK_ARGS") {
            result.warnings.push_back(std::format("unknown runtime variable '{}'", variable.name));
        }
    }

    if (!result.errors.empty()) {
        return std::nullopt;
    }
    return config;
}

std::optional<Runtime::Config> Runtime::checked_config(const Program& program, Result& result) {
    auto config = build_config(program, result);
    if (!config) {
        return std::nullopt;
    }

    Checker checker;
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
    checked_config(program, result);
    return result;
}

Runtime::Result Runtime::init(const Program& program, std::string_view eal_program_name) {
    Result result;
    auto config = checked_config(program, result);
    if (!config) {
        return result;
    }

    std::vector<std::string> argv_storage;
    argv_storage.reserve(config->dpdk_args.size() + 1);
    argv_storage.emplace_back(eal_program_name);
    argv_storage.insert(argv_storage.end(),
                        std::make_move_iterator(config->dpdk_args.begin()),
                        std::make_move_iterator(config->dpdk_args.end()));

    std::vector<char*> argv;
    argv.reserve(argv_storage.size());
    for (auto& arg : argv_storage) {
        argv.push_back(arg.data());
    }

    int parsed_args = rte_eal_init(static_cast<int>(argv.size()), argv.data());
    if (parsed_args < 0) {
        result.ok = false;
        result.errors.push_back(std::format("rte_eal_init failed: {}", rte_strerror(rte_errno)));
        return result;
    }

    result.ok = true;
    result.eal_parsed_args = parsed_args;
    return result;
}

} // namespace packet
