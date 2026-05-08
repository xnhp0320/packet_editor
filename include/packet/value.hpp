#pragma once

#include <array>
#include <compare>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace packet {

class MacAddr {
public:
    static std::optional<MacAddr> parse(std::string_view s);
    static MacAddr from_bytes(std::array<uint8_t, 6> b);

    std::span<const uint8_t> bytes() const { return bytes_; }
    std::string to_string() const;

    auto operator<=>(const MacAddr&) const = default;

private:
    explicit MacAddr(std::array<uint8_t, 6> b) : bytes_(b) {}
    std::array<uint8_t, 6> bytes_;
};

class IPv4 {
public:
    static std::optional<IPv4> parse(std::string_view s);
    static IPv4 from_bytes(std::array<uint8_t, 4> b);

    std::span<const uint8_t> bytes() const { return bytes_; }
    std::string to_string() const;

    auto operator<=>(const IPv4&) const = default;

private:
    explicit IPv4(std::array<uint8_t, 4> b) : bytes_(b) {}
    std::array<uint8_t, 4> bytes_;
};

class IPv6 {
public:
    static std::optional<IPv6> parse(std::string_view s);
    static IPv6 from_bytes(std::array<uint8_t, 16> b);

    std::span<const uint8_t> bytes() const { return bytes_; }
    std::string to_string() const;

    auto operator<=>(const IPv6&) const = default;

private:
    explicit IPv6(std::array<uint8_t, 16> b) : bytes_(b) {}
    std::array<uint8_t, 16> bytes_;
};

struct IPv4Range {
    IPv4 first;
    IPv4 last;

    auto operator<=>(const IPv4Range&) const = default;
};

struct IPv6Range {
    IPv6 first;
    IPv6 last;

    auto operator<=>(const IPv6Range&) const = default;
};

struct UIntRange {
    uint64_t first;
    uint64_t last;

    auto operator<=>(const UIntRange&) const = default;
};

using ConstructorValue = std::variant<
    uint64_t,
    MacAddr,
    IPv4,
    IPv6,
    IPv4Range,
    IPv6Range,
    std::vector<IPv4Range>,
    std::vector<IPv6Range>,
    std::vector<UIntRange>>;

} // namespace packet
