#include "packet/packet_generator.hpp"
#include "packet/parser.hpp"
#include "packet/pcap_writer.hpp"
#include "packet/registry.hpp"

#if PACKET_HAVE_DPDK
#include "packet/runtime.hpp"
#endif

#include <charconv>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace {

struct CliOptions {
    std::vector<std::string> positional;
    std::optional<std::string> packet_expression;
    std::optional<std::string> output_file;
    std::optional<uint64_t> packet_count;
    std::vector<std::string> errors;
};

struct FileProgram {
    packet::Packet packet;
    std::optional<uint64_t> packet_count;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
};

std::optional<std::string> read_file(const std::string& path) {
    std::ifstream input(path);
    if (!input) {
        return std::nullopt;
    }

    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

void print_usage(std::string_view program_name) {
    std::cerr << "usage:\n"
              << "  " << program_name << " <program-file>\n"
              << "  " << program_name << " <program-file> -o <pcap-file>\n"
              << "  " << program_name << " -e <packet-expression> -o <pcap-file> [-c <count>]\n";
}

std::optional<uint64_t> parse_positive_u64(std::string_view value, std::string& error) {
    uint64_t parsed = 0;
    const auto* first = value.data();
    const auto* last = first + value.size();
    auto [ptr, ec] = std::from_chars(first, last, parsed);
    if (ec != std::errc{} || ptr != last || parsed == 0) {
        error = "packet count must be a positive integer";
        return std::nullopt;
    }
    return parsed;
}

CliOptions parse_cli(int argc, char** argv) {
    CliOptions options;
    for (int index = 1; index < argc; ++index) {
        const std::string_view arg{argv[index]};
        auto require_value = [&](std::string_view option) -> std::optional<std::string> {
            if (index + 1 >= argc) {
                options.errors.push_back(std::string{option} + " requires a value");
                return std::nullopt;
            }
            ++index;
            return std::string{argv[index]};
        };

        if (arg == "-o") {
            if (options.output_file) {
                options.errors.emplace_back("-o may only be specified once");
                continue;
            }
            options.output_file = require_value(arg);
        } else if (arg == "-e") {
            if (options.packet_expression) {
                options.errors.emplace_back("-e may only be specified once");
                continue;
            }
            options.packet_expression = require_value(arg);
        } else if (arg == "-c") {
            if (options.packet_count) {
                options.errors.emplace_back("-c may only be specified once");
                continue;
            }
            auto value = require_value(arg);
            if (!value) {
                continue;
            }
            std::string error;
            auto count = parse_positive_u64(*value, error);
            if (!count) {
                options.errors.push_back(std::move(error));
                continue;
            }
            options.packet_count = *count;
        } else if (!arg.empty() && arg.front() == '-') {
            options.errors.push_back("unknown option '" + std::string{arg} + "'");
        } else {
            options.positional.emplace_back(arg);
        }
    }
    return options;
}

void print_messages(const std::vector<std::string>& warnings,
                    const std::vector<std::string>& errors) {
    for (const auto& warning : warnings) {
        std::cerr << "WARNING: " << warning << '\n';
    }
    for (const auto& error : errors) {
        std::cerr << "ERROR: " << error << '\n';
    }
}

#if PACKET_HAVE_DPDK
void print_runtime_messages(const packet::Runtime::Result& result) {
    print_messages(result.warnings, result.errors);
}
#endif

std::string strip_packet_prefix(std::string_view expression) {
    constexpr std::string_view prefix = "PACKET:";
    while (!expression.empty() &&
           (expression.front() == ' ' || expression.front() == '\t' ||
            expression.front() == '\n' || expression.front() == '\r')) {
        expression.remove_prefix(1);
    }
    if (expression.starts_with(prefix)) {
        expression.remove_prefix(prefix.size());
    }
    return std::string{expression};
}

FileProgram parse_packet_expression(std::string_view expression,
                                    std::optional<uint64_t> packet_count) {
    auto stripped = strip_packet_prefix(expression);
    packet::Parser parser(stripped);
    auto packet = parser.parse_packet();
    if (!packet) {
        FileProgram program;
        program.errors.push_back("parse failed: " + parser.last_error());
        return program;
    }

    FileProgram program;
    program.packet = std::move(*packet);
    program.packet_count = packet_count;
    return program;
}

FileProgram parse_file_program(std::string_view input,
                               std::optional<uint64_t> cli_packet_count) {
    packet::Parser parser(input);
    auto parsed = parser.parse();
    if (!parsed) {
        FileProgram program;
        program.errors.push_back("parse failed: " + parser.last_error());
        return program;
    }

    std::unordered_map<std::string_view, const packet::Variable*> variables;
    FileProgram program;
    for (const auto& variable : parsed->variables) {
        if (variables.contains(variable.name)) {
            program.errors.push_back("duplicate variable '" + variable.name + "'");
            continue;
        }
        variables.emplace(variable.name, &variable);
    }

    auto packet_it = variables.find("PACKET");
    if (packet_it == variables.end()) {
        program.errors.emplace_back("missing mandatory variable 'PACKET'");
    }

    auto packet_count_it = variables.find("PACKET_COUNT");
    if (packet_count_it != variables.end() && cli_packet_count) {
        program.errors.emplace_back("PACKET_COUNT and -c cannot both be specified");
    }

    if (!program.errors.empty()) {
        return program;
    }

    auto packet_value = packet::evaluate(packet_it->second->expression);
    if (!std::holds_alternative<packet::Packet>(packet_value)) {
        program.errors.emplace_back("variable 'PACKET' must be a packet expression");
    } else {
        program.packet = std::get<packet::Packet>(std::move(packet_value));
    }

    if (packet_count_it != variables.end()) {
        auto packet_count_value = packet::evaluate(packet_count_it->second->expression);
        if (!std::holds_alternative<int64_t>(packet_count_value)) {
            program.errors.emplace_back("variable 'PACKET_COUNT' must be an integer expression");
        } else {
            const auto packet_count = std::get<int64_t>(packet_count_value);
            if (packet_count <= 0) {
                program.errors.emplace_back("variable 'PACKET_COUNT' must be positive");
            } else {
                program.packet_count = static_cast<uint64_t>(packet_count);
            }
        }
    } else {
        program.packet_count = cli_packet_count;
    }

    for (const auto& variable : parsed->variables) {
        if (variable.name != "PACKET" && variable.name != "PACKET_COUNT" &&
            variable.name != "DPDK_ARGS") {
            program.warnings.push_back("unknown file-mode variable '" + variable.name + "'");
        }
    }
    return program;
}

int run_file_mode(const CliOptions& options) {
    if (options.positional.size() > 1) {
        std::cerr << "ERROR: file mode accepts at most one program file\n";
        return 2;
    }
    if (!options.positional.empty() && options.packet_expression) {
        std::cerr << "ERROR: specify either a program file or -e, not both\n";
        return 2;
    }
    if (options.positional.empty() && !options.packet_expression) {
        std::cerr << "ERROR: file mode requires a program file or -e\n";
        return 2;
    }

    FileProgram program;
    if (options.packet_expression) {
        program = parse_packet_expression(*options.packet_expression, options.packet_count);
    } else {
        auto input = read_file(options.positional.front());
        if (!input) {
            std::cerr << "ERROR: failed to read '" << options.positional.front() << "'\n";
            return 1;
        }
        program = parse_file_program(*input, options.packet_count);
    }
    if (!program.errors.empty()) {
        print_messages(program.warnings, program.errors);
        return 1;
    }

    packet::Registry registry;
    packet::PacketGenerator generator{registry};
    auto generated = generator.prepare(program.packet, program.packet_count);
    if (!generated.ok || !generated.packet) {
        program.warnings.insert(program.warnings.end(), generated.warnings.begin(), generated.warnings.end());
        print_messages(program.warnings, generated.errors);
        return 1;
    }

    std::ofstream output(*options.output_file, std::ios::binary);
    if (!output) {
        std::cerr << "ERROR: failed to open '" << *options.output_file << "' for writing\n";
        return 1;
    }

    packet::PcapWriter writer{output};
    auto write_result = writer.write_header();
    if (!write_result.ok) {
        print_messages({}, write_result.errors);
        return 1;
    }

    for (uint64_t flow_index = 0; flow_index < generated.packet->flow_plan.planned_packets; ++flow_index) {
        std::vector<std::byte> payload;
        if (!generator.payload_for_flow(*generated.packet, flow_index, payload, generated.errors)) {
            program.warnings.insert(program.warnings.end(), generated.warnings.begin(), generated.warnings.end());
            print_messages(program.warnings, generated.errors);
            return 1;
        }
        write_result = writer.write_packet(payload);
        if (!write_result.ok) {
            print_messages({}, write_result.errors);
            return 1;
        }
    }

    std::cout << "PCAP file written to '" << *options.output_file << "' with "
              << generated.packet->flow_plan.planned_packets << " packet(s), planned "
              << generated.packet->flow_plan.planned_packets << " of "
              << generated.packet->flow_plan.total_flows << " flow(s), packet_len "
              << generated.packet->packet_len << " bytes\n";
    program.warnings.insert(program.warnings.end(), generated.warnings.begin(), generated.warnings.end());
    print_messages(program.warnings, generated.errors);
    return 0;
}

int run_live_mode(const CliOptions& options, char** argv) {
    if (options.packet_expression || options.packet_count) {
        std::cerr << "ERROR: -e and -c are only valid in file mode with -o\n";
        return 2;
    }
    if (options.positional.size() != 1) {
        print_usage(argv[0]);
        return 2;
    }

#if PACKET_HAVE_DPDK
    auto input = read_file(options.positional.front());
    if (!input) {
        std::cerr << "ERROR: failed to read '" << options.positional.front() << "'\n";
        return 1;
    }

    packet::Parser parser(*input);
    auto program = parser.parse();
    if (!program) {
        std::cerr << "ERROR: parse failed: " << parser.last_error() << '\n';
        return 1;
    }

    packet::Runtime runtime;
    auto result = runtime.run(*program, argv[0]);
    print_runtime_messages(result);
    if (!result.ok) {
        return 1;
    }

    std::cout << "DPDK runtime completed; rte_eal_init parsed "
              << result.eal_parsed_args << " argument(s), port "
              << result.port_id << " sent " << result.tx_sent << '/'
              << result.tx_attempted << " packet(s), planned "
              << result.planned_packets << " of " << result.total_flows
              << " flow(s), packet_len " << result.packet_len
              << " bytes, pmd_threads " << result.pmd_threads
              << ", tx_batch_size " << result.tx_batch_size << '\n';
    for (const auto& worker : result.workers) {
        std::cout << "PMD worker " << worker.worker_id
                  << " lcore " << worker.lcore_id
                  << " queue " << worker.queue_id
                  << " sent " << worker.tx_sent << '/'
                  << worker.tx_attempted << " packet(s)\n";
    }
    return 0;
#else
    std::cerr << "ERROR: live mode requires a build with PACKET_BUILD_DPDK=ON\n";
    return 1;
#endif
}

} // namespace

int main(int argc, char** argv) {
    auto options = parse_cli(argc, argv);
    if (!options.errors.empty()) {
        print_messages({}, options.errors);
        print_usage(argv[0]);
        return 2;
    }

    if (options.output_file) {
        return run_file_mode(options);
    }
    return run_live_mode(options, argv);
}
