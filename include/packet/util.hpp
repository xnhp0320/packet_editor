#pragma once

#include "packet/ast.hpp"
#include "packet/value.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace packet {

std::string_view trim_ascii_whitespace(std::string_view s);

size_t bit_width_for_type_name(std::string_view type_name);
std::optional<size_t> bit_range_width_for_type_name(std::string_view type_name);
ConstructorValue default_constructor_value_for_type(std::string_view type_name);

std::optional<std::string> validate_bit_value(const ValueType& value, size_t bit_width);
std::optional<std::string> validate_bit_range_value(const ValueType& value, size_t bit_width);

std::optional<uint64_t> parse_uint_value(std::string_view raw, size_t bit_width, std::string& error);
std::optional<UIntRange> parse_uint_range(std::string_view raw, size_t bit_width, std::string& error);
std::optional<std::vector<UIntRange>> parse_uint_ranges(std::string_view raw, size_t bit_width, std::string& error);
std::optional<IPv4Range> parse_ipv4_range(std::string_view raw, std::string& error);
std::optional<IPv6Range> parse_ipv6_range(std::string_view raw, std::string& error);
std::optional<std::vector<IPv4Range>> parse_ipv4_ranges(std::string_view raw, std::string& error);
std::optional<std::vector<IPv6Range>> parse_ipv6_ranges(std::string_view raw, std::string& error);

} // namespace packet
