#include "packet/packet_constructor.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <format>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace packet {

namespace {

std::string_view trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
        s.remove_prefix(1);
    }
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
        s.remove_suffix(1);
    }
    return s;
}

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

std::optional<IPv4Range> parse_ipv4_range(std::string_view raw, std::string& error) {
    auto s = trim(raw);
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
        auto left = IPv4::parse(trim(s.substr(0, dash)));
        auto right = IPv4::parse(trim(s.substr(dash + 1)));
        if (!left) {
            error = std::format("invalid ipv4 address '{}'", trim(s.substr(0, dash)));
            return std::nullopt;
        }
        if (!right) {
            error = std::format("invalid ipv4 address '{}'", trim(s.substr(dash + 1)));
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
    auto s = trim(raw);
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
        auto left = IPv6::parse(trim(s.substr(0, dash)));
        auto right = IPv6::parse(trim(s.substr(dash + 1)));
        if (!left) {
            error = std::format("invalid ipv6 address '{}'", trim(s.substr(0, dash)));
            return std::nullopt;
        }
        if (!right) {
            error = std::format("invalid ipv6 address '{}'", trim(s.substr(dash + 1)));
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

template <typename Range>
std::optional<std::vector<Range>> parse_range_list(
    std::string_view raw,
    std::string& error,
    std::optional<Range> (*parse_one)(std::string_view, std::string&)) {
    auto s = trim(raw);
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
    if (trim(content).empty()) {
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
        item = trim(item);
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

std::optional<ConstructorValue> construct_value(const FieldSpec& field,
                                                const ValueType& value,
                                                std::string& error) {
    if (!field.type_name) {
        if (std::holds_alternative<int64_t>(value) && std::get<int64_t>(value) >= 0) {
            return ConstructorValue{static_cast<uint64_t>(std::get<int64_t>(value))};
        }
        error = "untyped constructor fields only support non-negative integer values";
        return std::nullopt;
    }

    const auto type = std::string_view{*field.type_name};
    if (type.starts_with('b')) {
        if (!std::holds_alternative<int64_t>(value)) {
            error = "expected integer value";
            return std::nullopt;
        }
        auto integer = std::get<int64_t>(value);
        if (integer < 0) {
            error = "negative integer value";
            return std::nullopt;
        }
        if (field.bit_width < 64) {
            const auto max = (uint64_t{1} << field.bit_width) - 1;
            if (static_cast<uint64_t>(integer) > max) {
                error = std::format("value {} does not fit in {} bits", integer, field.bit_width);
                return std::nullopt;
            }
        }
        return ConstructorValue{static_cast<uint64_t>(integer)};
    }
    if (!std::holds_alternative<std::string>(value)) {
        error = std::format("{} value must be a string", type);
        return std::nullopt;
    }

    const auto& string = std::get<std::string>(value);
    if (type == "mac") {
        auto mac = MacAddr::parse(string);
        if (!mac) {
            error = std::format("invalid mac address '{}'", string);
            return std::nullopt;
        }
        return ConstructorValue{*mac};
    }
    if (type == "ipv4") {
        auto ip = IPv4::parse(string);
        if (!ip) {
            error = std::format("invalid ipv4 address '{}'", string);
            return std::nullopt;
        }
        return ConstructorValue{*ip};
    }
    if (type == "ipv6") {
        auto ip = IPv6::parse(string);
        if (!ip) {
            error = std::format("invalid ipv6 address '{}'", string);
            return std::nullopt;
        }
        return ConstructorValue{*ip};
    }
    if (type == "ipv4_range") {
        auto range = parse_ipv4_range(string, error);
        if (!range) {
            return std::nullopt;
        }
        return ConstructorValue{*range};
    }
    if (type == "ipv6_range") {
        auto range = parse_ipv6_range(string, error);
        if (!range) {
            return std::nullopt;
        }
        return ConstructorValue{*range};
    }
    if (type == "ipv4_ranges") {
        auto ranges = parse_range_list<IPv4Range>(string, error, parse_ipv4_range);
        if (!ranges) {
            return std::nullopt;
        }
        return ConstructorValue{*ranges};
    }
    if (type == "ipv6_ranges") {
        auto ranges = parse_range_list<IPv6Range>(string, error, parse_ipv6_range);
        if (!ranges) {
            return std::nullopt;
        }
        return ConstructorValue{*ranges};
    }

    error = std::format("unsupported constructor type '{}'", type);
    return std::nullopt;
}

} // namespace

PacketConstructorBuilder::PacketConstructorBuilder(const Registry& registry)
    : registry_(registry)
{
}

PacketConstructorBuilder::Result PacketConstructorBuilder::build(const Packet& packet) const {
    Result result;
    PacketConstructor constructor;
    size_t packet_bit_offset = 0;

    for (const auto& header : packet) {
        const auto* header_spec = registry_.find_header(header.protocol);
        if (!header_spec) {
            result.errors.push_back(std::format("unknown header: '{}'", header.protocol));
            continue;
        }
        if (packet_bit_offset % 8 != 0) {
            result.errors.push_back(std::format("header '{}' starts at non-byte offset {}",
                                                header.protocol, packet_bit_offset));
            continue;
        }

        std::unordered_map<std::string_view, const Attribute*> attrs;
        for (const auto& attr : header.attributes) {
            if (attrs.contains(attr.name)) {
                result.errors.push_back(std::format("duplicate attribute '{}' in header '{}'",
                                                    attr.name, header.protocol));
                continue;
            }
            attrs.emplace(attr.name, &attr);
        }

        HeaderConstructor header_constructor{
            header.protocol,
            packet_bit_offset / 8,
            {},
        };
        header_constructor.fields.reserve(header_spec->fields.size());

        for (const auto& field : header_spec->fields) {
            auto attr_it = attrs.find(field.name);
            if (attr_it == attrs.end()) {
                header_constructor.fields.push_back(FieldConstructor{
                    field.name,
                    field.default_value,
                    false,
                });
                continue;
            }

            const auto& attr = *attr_it->second;
            if (!attr.value) {
                result.errors.push_back(std::format("attribute '{}' in header '{}' requires a value",
                                                    attr.name, header.protocol));
                continue;
            }

            std::string error;
            auto value = construct_value(field, *attr.value, error);
            if (!value) {
                result.errors.push_back(std::format("invalid '{}' in header '{}': {}",
                                                    attr.name, header.protocol, error));
                continue;
            }
            header_constructor.fields.push_back(FieldConstructor{
                field.name,
                std::move(*value),
                true,
            });
        }

        for (const auto& [name, attr] : attrs) {
            auto known = std::ranges::any_of(header_spec->fields, [name](const FieldSpec& field) {
                return field.name == name;
            });
            if (!known) {
                result.errors.push_back(std::format("unknown attribute '{}' in header '{}'",
                                                    name, header.protocol));
            }
        }

        constructor.push_back(std::move(header_constructor));
        packet_bit_offset += header_spec->bit_width;
    }

    if (!result.errors.empty()) {
        result.ok = false;
        return result;
    }

    result.ok = true;
    result.packet = std::move(constructor);
    return result;
}

} // namespace packet
