#include "packet/parser.hpp"
#include "packet/runtime.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>

namespace {

std::optional<std::string> read_file(const char* path) {
    std::ifstream input(path);
    if (!input) {
        return std::nullopt;
    }

    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

void print_messages(const packet::Runtime::Result& result) {
    for (const auto& warning : result.warnings) {
        std::cerr << "WARNING: " << warning << '\n';
    }
    for (const auto& error : result.errors) {
        std::cerr << "ERROR: " << error << '\n';
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <program-file>\n";
        return 2;
    }

    auto input = read_file(argv[1]);
    if (!input) {
        std::cerr << "ERROR: failed to read '" << argv[1] << "'\n";
        return 1;
    }

    packet::Parser parser(*input);
    auto program = parser.parse();
    if (!program) {
        std::cerr << "ERROR: parse failed: " << parser.last_error() << '\n';
        return 1;
    }

    packet::Runtime runtime;
    auto result = runtime.init(*program, argv[0]);
    print_messages(result);
    if (!result.ok) {
        return 1;
    }

    std::cout << "DPDK initialized; rte_eal_init parsed "
              << result.eal_parsed_args << " argument(s)\n";
    return 0;
}
