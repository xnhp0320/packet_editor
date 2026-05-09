#include "packet/util.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <format>

namespace packet {

std::string_view trim_ascii_whitespace(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
        s.remove_prefix(1);
    }
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
        s.remove_suffix(1);
    }
    return s;
}

size_t bit_width_for_type_name(std::string_view type_name) {
    if (type_name == "mac") {
        return 48;
    }
    if (type_name == "ipv4" || type_name == "ipv4_range" || type_name == "ipv4_ranges") {
        return 32;
    }
    if (type_name == "ipv6" || type_name == "ipv6_range" || type_name == "ipv6_ranges") {
        return 128;
    }
    if (auto width = bit_range_width_for_type_name(type_name)) {
        return *width;
    }
    if (type_name.starts_with('b')) {
        size_t width = 0;
        auto digits = type_name.substr(1);
        auto [ptr, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), width);
        if (ec == std::errc{} && ptr == digits.data() + digits.size()) {
            return width;
        }
    }
    return 0;
}

std::optional<size_t> bit_range_width_for_type_name(std::string_view type_name) {
    constexpr std::string_view suffix = "_ranges";
    if (!type_name.starts_with('b') || !type_name.ends_with(suffix)) {
        return std::nullopt;
    }

    const auto digits = type_name.substr(1, type_name.size() - 1 - suffix.size());
    size_t width = 0;
    auto [ptr, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), width);
    if (ec != std::errc{} || ptr != digits.data() + digits.size() || width < 1 || width > 64) {
        return std::nullopt;
    }
    return width;
}

ConstructorValue default_constructor_value_for_type(std::string_view type_name) {
    if (type_name == "mac") {
        return MacAddr::from_bytes({});
    }
    if (type_name == "ipv4") {
        return IPv4::from_bytes({});
    }
    if (type_name == "ipv6") {
        return IPv6::from_bytes({});
    }
    if (type_name == "ipv4_range") {
        auto zero = IPv4::from_bytes({});
        return IPv4Range{zero, zero};
    }
    if (type_name == "ipv6_range") {
        auto zero = IPv6::from_bytes({});
        return IPv6Range{zero, zero};
    }
    if (type_name == "ipv4_ranges") {
        auto zero = IPv4::from_bytes({});
        return std::vector<IPv4Range>{IPv4Range{zero, zero}};
    }
    if (type_name == "ipv6_ranges") {
        auto zero = IPv6::from_bytes({});
        return std::vector<IPv6Range>{IPv6Range{zero, zero}};
    }
    return uint64_t{0};
}

std::optional<std::string> validate_bit_value(const ValueType& value, size_t bit_width) {
    if (!std::holds_alternative<int64_t>(value)) {
        return std::string{"expected integer value"};
    }

    const auto integer = std::get<int64_t>(value);
    if (bit_width < 64) {
        const auto max = (uint64_t{1} << bit_width) - 1;
        if (integer < 0 || static_cast<uint64_t>(integer) > max) {
            return std::format("value {} does not fit in {} bits", integer, bit_width);
        }
        return std::nullopt;
    }

    if (integer < 0) {
        return std::format("negative value {} does not fit in 64 bits", integer);
    }
    return std::nullopt;
}

std::optional<std::string> validate_bit_range_value(const ValueType& value, size_t bit_width) {
    if (std::holds_alternative<int64_t>(value)) {
        return validate_bit_value(value, bit_width);
    }
    if (!std::holds_alternative<std::string>(value)) {
        return std::string{"expected integer or string value"};
    }

    const auto raw = trim_ascii_whitespace(std::get<std::string>(value));
    std::string error;
    if (raw.starts_with('[') || raw.ends_with(']') || raw.find('-') != std::string_view::npos) {
        if (!parse_uint_ranges(raw, bit_width, error)) {
            return error;
        }
        return std::nullopt;
    }
    if (!parse_uint_value(raw, bit_width, error)) {
        return error;
    }
    return std::nullopt;
}

namespace {

std::array<uint8_t, 4> ipv4_bytes(const IPv4& ip) {
    std::array<uint8_t, 4> bytes{};
    std::ranges::copy(ip.bytes(), bytes.begin());
    return bytes;
}

std::array<uint8_t, 16> ipv6_bytes(const IPv6& ip) {
    std::array<uint8_t, 16> bytes{};
    std::ranges::copy(ip.bytes(), bytes.begin());
    return bytes;
}

uint32_t ipv4_to_u32(const IPv4& ip) {
    auto bytes = ipv4_bytes(ip);
    return (static_cast<uint32_t>(bytes[0]) << 24) |
           (static_cast<uint32_t>(bytes[1]) << 16) |
           (static_cast<uint32_t>(bytes[2]) << 8) |
           static_cast<uint32_t>(bytes[3]);
}

IPv4 ipv4_from_u32(uint32_t value) {
    return IPv4::from_bytes({
        static_cast<uint8_t>(value >> 24),
        static_cast<uint8_t>((value >> 16) & 0xff),
        static_cast<uint8_t>((value >> 8) & 0xff),
        static_cast<uint8_t>(value & 0xff),
    });
}

std::optional<int> parse_prefix(std::string_view s, int max_prefix, std::string& error) {
    if (s.empty()) {
        error = "empty CIDR mask";
        return std::nullopt;
    }

    int prefix = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), prefix);
    if (ec != std::errc{} || ptr != s.data() + s.size()) {
        error = std::format("invalid CIDR mask '{}'", s);
        return std::nullopt;
    }
    if (prefix < 0 || prefix > max_prefix) {
        error = std::format("CIDR mask {} out of range [0,{}]", prefix, max_prefix);
        return std::nullopt;
    }
    return prefix;
}

template <typename Range, typename ParseOne>
std::optional<std::vector<Range>> parse_range_list(
    std::string_view raw,
    std::string& error,
    ParseOne parse_one) {
    auto s = trim_ascii_whitespace(raw);
    if (!s.starts_with('[') && !s.ends_with(']')) {
        auto range = parse_one(s, error);
        if (!range) {
            return std::nullopt;
        }
        return std::vector<Range>{*range};
    }
    if (!s.starts_with('[') || !s.ends_with(']')) {
        error = std::format("malformed range list '{}'", raw);
        return std::nullopt;
    }

    auto content = s.substr(1, s.size() - 2);
    if (trim_ascii_whitespace(content).empty()) {
        error = "empty range list";
        return std::nullopt;
    }

    std::vector<Range> ranges;
    size_t index = 0;
    size_t start = 0;
    while (start <= content.size()) {
        auto comma = content.find(',', start);
        auto item = comma == std::string_view::npos
                  ? content.substr(start)
                  : content.substr(start, comma - start);
        item = trim_ascii_whitespace(item);
        if (item.empty()) {
            error = std::format("empty range at index {}", index);
            return std::nullopt;
        }
        auto range = parse_one(item, error);
        if (!range) {
            error = std::format("invalid range at index {}: {}", index, error);
            return std::nullopt;
        }
        ranges.push_back(*range);
        if (comma == std::string_view::npos) {
            break;
        }
        start = comma + 1;
        ++index;
    }
    return ranges;
}

} // namespace

std::optional<uint64_t> parse_uint_value(std::string_view raw, size_t bit_width, std::string& error) {
    auto s = trim_ascii_whitespace(raw);
    if (s.empty()) {
        error = "empty integer value";
        return std::nullopt;
    }

    int base = 10;
    if (s.starts_with("0x") || s.starts_with("0X")) {
        base = 16;
        s.remove_prefix(2);
    } else if (s.starts_with("0b") || s.starts_with("0B")) {
        base = 2;
        s.remove_prefix(2);
    }
    if (s.empty()) {
        error = std::format("invalid integer value '{}'", raw);
        return std::nullopt;
    }

    uint64_t value = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value, base);
    if (ec != std::errc{} || ptr != s.data() + s.size()) {
        error = std::format("invalid integer value '{}'", raw);
        return std::nullopt;
    }

    if (bit_width < 64) {
        const auto max = (uint64_t{1} << bit_width) - 1;
        if (value > max) {
            error = std::format("value {} does not fit in {} bits", value, bit_width);
            return std::nullopt;
        }
    }

    return value;
}

std::optional<UIntRange> parse_uint_range(std::string_view raw, size_t bit_width, std::string& error) {
    auto s = trim_ascii_whitespace(raw);
    if (auto dash = s.find('-'); dash != std::string_view::npos) {
        auto left = parse_uint_value(s.substr(0, dash), bit_width, error);
        if (!left) {
            return std::nullopt;
        }
        auto right = parse_uint_value(s.substr(dash + 1), bit_width, error);
        if (!right) {
            return std::nullopt;
        }
        if (*left > *right) {
            error = std::format("range start {} is greater than range end {}", *left, *right);
            return std::nullopt;
        }
        return UIntRange{*left, *right};
    }

    auto value = parse_uint_value(s, bit_width, error);
    if (!value) {
        return std::nullopt;
    }
    return UIntRange{*value, *value};
}

std::optional<std::vector<UIntRange>> parse_uint_ranges(std::string_view raw,
                                                        size_t bit_width,
                                                        std::string& error) {
    return parse_range_list<UIntRange>(
        raw,
        error,
        [bit_width](std::string_view item, std::string& item_error) -> std::optional<UIntRange> {
            return parse_uint_range(item, bit_width, item_error);
        });
}

std::optional<IPv4Range> parse_ipv4_range(std::string_view raw, std::string& error) {
    auto s = trim_ascii_whitespace(raw);
    if (auto slash = s.find('/'); slash != std::string_view::npos) {
        auto ip = IPv4::parse(s.substr(0, slash));
        if (!ip) {
            error = std::format("invalid ipv4 address '{}'", s.substr(0, slash));
            return std::nullopt;
        }
        auto prefix = parse_prefix(s.substr(slash + 1), 32, error);
        if (!prefix) {
            return std::nullopt;
        }

        const uint32_t mask = *prefix == 0 ? 0 : ~uint32_t{0} << (32 - *prefix);
        const auto base = ipv4_to_u32(*ip);
        return IPv4Range{ipv4_from_u32(base & mask), ipv4_from_u32(base | ~mask)};
    }

    if (auto dash = s.find('-'); dash != std::string_view::npos) {
        auto left = IPv4::parse(trim_ascii_whitespace(s.substr(0, dash)));
        auto right = IPv4::parse(trim_ascii_whitespace(s.substr(dash + 1)));
        if (!left) {
            error = std::format("invalid ipv4 address '{}'", trim_ascii_whitespace(s.substr(0, dash)));
            return std::nullopt;
        }
        if (!right) {
            error = std::format("invalid ipv4 address '{}'", trim_ascii_whitespace(s.substr(dash + 1)));
            return std::nullopt;
        }
        return IPv4Range{*left, *right};
    }

    auto ip = IPv4::parse(s);
    if (!ip) {
        error = std::format("invalid ipv4 address '{}'", s);
        return std::nullopt;
    }
    return IPv4Range{*ip, *ip};
}

std::optional<IPv6Range> parse_ipv6_range(std::string_view raw, std::string& error) {
    auto s = trim_ascii_whitespace(raw);
    if (auto slash = s.find('/'); slash != std::string_view::npos) {
        auto ip = IPv6::parse(s.substr(0, slash));
        if (!ip) {
            error = std::format("invalid ipv6 address '{}'", s.substr(0, slash));
            return std::nullopt;
        }
        auto prefix = parse_prefix(s.substr(slash + 1), 128, error);
        if (!prefix) {
            return std::nullopt;
        }

        auto first = ipv6_bytes(*ip);
        auto last = first;
        for (int bit = *prefix; bit < 128; ++bit) {
            const auto byte = static_cast<size_t>(bit / 8);
            const auto mask = static_cast<uint8_t>(1u << (7 - bit % 8));
            first[byte] = static_cast<uint8_t>(first[byte] & ~mask);
            last[byte] = static_cast<uint8_t>(last[byte] | mask);
        }
        return IPv6Range{IPv6::from_bytes(first), IPv6::from_bytes(last)};
    }

    if (auto dash = s.find('-'); dash != std::string_view::npos) {
        auto left = IPv6::parse(trim_ascii_whitespace(s.substr(0, dash)));
        auto right = IPv6::parse(trim_ascii_whitespace(s.substr(dash + 1)));
        if (!left) {
            error = std::format("invalid ipv6 address '{}'", trim_ascii_whitespace(s.substr(0, dash)));
            return std::nullopt;
        }
        if (!right) {
            error = std::format("invalid ipv6 address '{}'", trim_ascii_whitespace(s.substr(dash + 1)));
            return std::nullopt;
        }
        return IPv6Range{*left, *right};
    }

    auto ip = IPv6::parse(s);
    if (!ip) {
        error = std::format("invalid ipv6 address '{}'", s);
        return std::nullopt;
    }
    return IPv6Range{*ip, *ip};
}

std::optional<std::vector<IPv4Range>> parse_ipv4_ranges(std::string_view raw, std::string& error) {
    return parse_range_list<IPv4Range>(raw, error, parse_ipv4_range);
}

std::optional<std::vector<IPv6Range>> parse_ipv6_ranges(std::string_view raw, std::string& error) {
    return parse_range_list<IPv6Range>(raw, error, parse_ipv6_range);
}

} // namespace packet
