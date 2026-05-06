#pragma once

#include "packet/ast.hpp"
#include "packet/registry.hpp"

#include <string>
#include <vector>

namespace packet {

class Checker {
public:
    using AttrSpec = packet::AttrSpec;

    struct Result {
        bool ok;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
    };

    Checker(const TypeRegistry& type_validators,
            const AttrNameRegistry& attr_names,
            const AttrTypeRegistry& attr_types);
    explicit Checker(const Registry& registry);

    Result check(const Packet& packet) const;
    void validate_or_exit(const Packet& packet) const;

private:
    const TypeRegistry& type_validators_;
    const AttrNameRegistry& attr_names_;
    const AttrTypeRegistry& attr_types_;
};

} // namespace packet
