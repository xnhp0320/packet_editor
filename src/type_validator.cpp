#include "packet/type_validator.hpp"
#include "packet/value.hpp"

#include <format>
#include <string>

namespace packet {

std::optional<std::string> MacAddrValidator::validate(const ValueType& value) const {
    if (!std::holds_alternative<std::string>(value)) {
        return std::string{"mac address must be a string value"};
    }
    const auto& s = std::get<std::string>(value);
    if (!MacAddr::parse(s)) {
        return std::format("invalid mac address '{}'", s);
    }
    return std::nullopt;
}

std::optional<std::string> IPv4Validator::validate(const ValueType& value) const {
    if (!std::holds_alternative<std::string>(value)) {
        return std::string{"ipv4 address must be a string value"};
    }
    const auto& s = std::get<std::string>(value);
    if (!IPv4::parse(s)) {
        return std::format("invalid ipv4 address '{}'", s);
    }
    return std::nullopt;
}

std::optional<std::string> IPv6Validator::validate(const ValueType& value) const {
    if (!std::holds_alternative<std::string>(value)) {
        return std::string{"ipv6 address must be a string value"};
    }
    const auto& s = std::get<std::string>(value);
    if (!IPv6::parse(s)) {
        return std::format("invalid ipv6 address '{}'", s);
    }
    return std::nullopt;
}

std::optional<std::string> IPv4RangeValidator::validate(const ValueType& value) const {
    if (!std::holds_alternative<std::string>(value)) {
        return IPv4Validator{}.validate(value);
    }

    std::string error;
    if (!parse_ipv4_range(std::get<std::string>(value), error)) {
        return error;
    }
    return std::nullopt;
}

std::optional<std::string> IPv6RangeValidator::validate(const ValueType& value) const {
    if (!std::holds_alternative<std::string>(value)) {
        return IPv6Validator{}.validate(value);
    }

    std::string error;
    if (!parse_ipv6_range(std::get<std::string>(value), error)) {
        return error;
    }
    return std::nullopt;
}

std::optional<std::string> IPv4RangeListValidator::validate(const ValueType& value) const {
    if (!std::holds_alternative<std::string>(value)) {
        return IPv4RangeValidator{}.validate(value);
    }

    std::string error;
    if (!parse_ipv4_ranges(std::get<std::string>(value), error)) {
        return error;
    }
    return std::nullopt;
}

std::optional<std::string> IPv6RangeListValidator::validate(const ValueType& value) const {
    if (!std::holds_alternative<std::string>(value)) {
        return IPv6RangeValidator{}.validate(value);
    }

    std::string error;
    if (!parse_ipv6_ranges(std::get<std::string>(value), error)) {
        return error;
    }
    return std::nullopt;
}

} // namespace packet
