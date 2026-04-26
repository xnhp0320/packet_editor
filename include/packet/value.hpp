#pragma once

#include <array>
#include <compare>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace packet {

class MacAddr {
public:
    static std::optional<MacAddr> parse(std::string_view s);

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

    std::span<const uint8_t> bytes() const { return bytes_; }
    std::string to_string() const;

    auto operator<=>(const IPv6&) const = default;

private:
    explicit IPv6(std::array<uint8_t, 16> b) : bytes_(b) {}
    std::array<uint8_t, 16> bytes_;
};

} // namespace packet
