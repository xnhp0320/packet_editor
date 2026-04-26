#include "packet/type_validator.hpp"

#include <algorithm>
#include <cctype>
#include <format>
#include <string>

namespace packet {

static std::optional<std::string> extract_string(const ValueType& value) {
    if (!std::holds_alternative<std::string>(value)) {
        return std::nullopt;
    }
    return std::get<std::string>(value);
}

static bool is_hex_digit(char c) {
    return std::isxdigit(static_cast<unsigned char>(c));
}

std::optional<std::string> MacAddrValidator::validate(const ValueType& value) const {
    auto str_opt = extract_string(value);
    if (!str_opt) {
        return std::string{"mac address must be a string value"};
    }
    const auto& s = *str_opt;

    if (s.size() != 17) {
        return std::format("mac address must be 17 characters (xx:xx:xx:xx:xx:xx), got {}", s.size());
    }

    for (size_t i = 0; i < 17; ++i) {
        if (i % 3 == 2) {
            if (s[i] != ':') {
                return std::format("expected ':' at position {} in mac address '{}'", i, s);
            }
        } else {
            if (!is_hex_digit(s[i])) {
                return std::format("invalid hex digit at position {} in mac address '{}'", i, s);
            }
        }
    }
    return std::nullopt;
}

std::optional<std::string> IPv4Validator::validate(const ValueType& value) const {
    auto str_opt = extract_string(value);
    if (!str_opt) {
        return std::string{"ipv4 address must be a string value"};
    }
    const auto& s = *str_opt;

    size_t dots = std::count(s.begin(), s.end(), '.');
    if (dots != 3) {
        return std::format("ipv4 address '{}' does not have 3 dots", s);
    }

    size_t start = 0;
    for (int octet = 0; octet < 4; ++octet) {
        size_t end = s.find('.', start);
        if (end == std::string::npos) {
            end = s.size();
        }
        auto part = s.substr(start, end - start);
        if (part.empty() || part.size() > 3) {
            return std::format("invalid ipv4 octet '{}' in '{}'", part, s);
        }
        for (char c : part) {
            if (!std::isdigit(static_cast<unsigned char>(c))) {
                return std::format("invalid ipv4 octet '{}' in '{}'", part, s);
            }
        }
        int val = std::stoi(part);
        if (val < 0 || val > 255) {
            return std::format("ipv4 octet {} out of range [0,255] in '{}'", val, s);
        }
        start = end + 1;
    }
    return std::nullopt;
}

static bool is_hex_quartet(std::string_view s) {
    if (s.empty() || s.size() > 4) return false;
    return std::all_of(s.begin(), s.end(), [](char c) {
        return std::isxdigit(static_cast<unsigned char>(c));
    });
}

std::optional<std::string> IPv6Validator::validate(const ValueType& value) const {
    auto str_opt = extract_string(value);
    if (!str_opt) {
        return std::string{"ipv6 address must be a string value"};
    }
    const auto& s = *str_opt;

    if (s == "::") {
        return std::nullopt;
    }

    auto dcolon_pos = s.find("::");
    if (dcolon_pos != std::string::npos) {
        if (s.find("::", dcolon_pos + 2) != std::string::npos) {
            return std::format("ipv6 address '{}' has more than one '::'", s);
        }

        auto left = (dcolon_pos == 0) ? std::string_view{} : std::string_view{s.data(), dcolon_pos};
        auto right = (dcolon_pos + 2 >= s.size()) ? std::string_view{} : std::string_view{s.data() + dcolon_pos + 2};

        size_t left_count = 0;
        size_t start = 0;
        while (start < left.size()) {
            auto end = left.find(':', start);
            if (end == std::string_view::npos) end = left.size();
            if (!is_hex_quartet(left.substr(start, end - start))) {
                return std::format("invalid ipv6 group '{}' in '{}'", std::string(left.substr(start, end - start)), s);
            }
            ++left_count;
            start = end + 1;
        }

        size_t right_count = 0;
        start = 0;
        while (start < right.size()) {
            auto end = right.find(':', start);
            if (end == std::string_view::npos) end = right.size();
            if (!is_hex_quartet(right.substr(start, end - start))) {
                return std::format("invalid ipv6 group '{}' in '{}'", std::string(right.substr(start, end - start)), s);
            }
            ++right_count;
            start = end + 1;
        }

        if (left_count + right_count > 7) {
            return std::format("ipv6 address '{}' has too many groups ({}+{})", s, left_count, right_count);
        }
    } else {
        size_t count = 0;
        size_t start = 0;
        while (start < s.size()) {
            auto end = s.find(':', start);
            if (end == std::string::npos) end = s.size();
            if (!is_hex_quartet(s.substr(start, end - start))) {
                return std::format("invalid ipv6 group '{}' in '{}'", std::string(s.substr(start, end - start)), s);
            }
            ++count;
            start = end + 1;
        }
        if (count != 8) {
            return std::format("ipv6 address '{}' must have exactly 8 groups (or use :: compression)", s);
        }
    }
    return std::nullopt;
}

} // namespace packet
