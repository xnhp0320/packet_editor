#pragma once

#include "packet/ast.hpp"
#include "packet/type_validator.hpp"

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace packet {

class Checker {
public:
    struct AttrSpec {
        std::string name;
        std::optional<std::string> type_name;
    };

    struct Result {
        bool ok;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
    };

    Checker();

    Checker& register_type(std::string type_name, std::unique_ptr<TypeValidator> validator);
    Checker& register_header(std::string protocol, std::vector<AttrSpec> attrs);

    Result check(const Packet& packet) const;
    void validate_or_exit(const Packet& packet) const;

private:
    std::unordered_map<std::string, std::unique_ptr<TypeValidator>> type_validators_;
    std::unordered_map<std::string, std::unordered_set<std::string>> attr_names_;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> attr_types_;
};

} // namespace packet
