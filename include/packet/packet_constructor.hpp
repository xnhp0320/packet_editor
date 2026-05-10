#pragma once

#include "packet/ast.hpp"
#include "packet/registry.hpp"
#include "packet/value.hpp"

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace packet {

struct HeaderConstructor;
using PacketConstructor = std::vector<HeaderConstructor>;

struct FieldConstructor {
    std::string name;
    ConstructorValue value;
    bool explicitly_set = false;
};

struct OptionConstructor {
    std::string name;
    std::variant<ConstructorValue, std::shared_ptr<PacketConstructor>> value;
    bool explicitly_set = false;
};

struct HeaderConstructor {
    std::string protocol;
    size_t offset = 0;
    std::vector<FieldConstructor> fields;
    std::vector<OptionConstructor> options;
};

class PacketConstructorBuilder {
public:
    struct Result {
        bool ok = false;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
        std::optional<PacketConstructor> packet;
    };

    explicit PacketConstructorBuilder(const Registry& registry);

    Result build(const Packet& packet) const;

private:
    const Registry& registry_;
};

} // namespace packet
