#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace packet {

using ValueType = std::variant<std::string, int64_t>;

struct Attribute {
    std::string name;
    std::optional<ValueType> value;
};

struct Header {
    std::string protocol;
    std::vector<Attribute> attributes;
};

using Packet = std::vector<Header>;

inline Packet operator/(Header h1, Header h2) {
    Packet p;
    p.push_back(std::move(h1));
    p.push_back(std::move(h2));
    return p;
}

inline Packet operator/(Packet p, Header h) {
    p.push_back(std::move(h));
    return p;
}

} // namespace packet
