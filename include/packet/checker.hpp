#pragma once

#include "packet/ast.hpp"

#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace packet {

class Checker {
public:
    struct Result {
        bool ok;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
    };

    Checker();

    Checker& register_header(std::string protocol, std::vector<std::string> known_attrs);

    Result check(const Packet& packet) const;

    void validate_or_exit(const Packet& packet) const;

private:
    std::unordered_map<std::string, std::unordered_set<std::string>> known_headers_;
};

} // namespace packet
