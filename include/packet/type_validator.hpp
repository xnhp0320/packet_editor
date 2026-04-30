#pragma once

#include "packet/ast.hpp"

#include <cctype>
#include <concepts>
#include <cstdint>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace packet {

class TypeValidator {
public:
    virtual ~TypeValidator() = default;
    virtual std::optional<std::string> validate(const ValueType& value) const = 0;
};

class MacAddrValidator : public TypeValidator {
public:
    std::optional<std::string> validate(const ValueType& value) const override;
};

class IPv4Validator : public TypeValidator {
public:
    std::optional<std::string> validate(const ValueType& value) const override;
};

class IPv6Validator : public TypeValidator {
public:
    std::optional<std::string> validate(const ValueType& value) const override;
};

template <size_t N>
requires (N >= 1 && N <= 64)
class BitsValidator : public TypeValidator {
public:
    std::optional<std::string> validate(const ValueType& value) const override {
        if (!std::holds_alternative<int64_t>(value)) {
            return std::string{"expected integer value"};
        }
        auto v = std::get<int64_t>(value);
        if constexpr (N < 64) {
            constexpr uint64_t mask = (1ULL << N) - 1;
            if (v < 0 || static_cast<uint64_t>(v) > mask) {
                return std::format("value {} does not fit in {} bits", v, N);
            }
        } else {
            if (v < 0) {
                return std::format("negative value {} does not fit in 64 bits", v);
            }
        }
        return std::nullopt;
    }
};

template <typename T, int MaxPrefix = -1>
requires std::derived_from<T, TypeValidator>
class RangeValidator : public TypeValidator {
    T inner_;
public:
    std::optional<std::string> validate(const ValueType& value) const override {
        if (!std::holds_alternative<std::string>(value)) {
            return inner_.validate(value);
        }
        const auto& s = std::get<std::string>(value);

        if constexpr (MaxPrefix > 0) {
            auto slash = s.find('/');
            if (slash != std::string::npos) {
                auto prefix = s.substr(0, slash);
                auto mask_str = s.substr(slash + 1);
                auto inner_err = inner_.validate(ValueType{std::string(prefix)});
                if (inner_err) return inner_err;

                if (mask_str.empty()) {
                    return std::format("empty CIDR mask in '{}'", s);
                }
                for (char c : mask_str) {
                    if (!std::isdigit(static_cast<unsigned char>(c))) {
                        return std::format("invalid CIDR mask '{}'", mask_str);
                    }
                }
                int mask = std::stoi(mask_str);
                if (mask < 0 || mask > MaxPrefix) {
                    return std::format("CIDR mask {} out of range [0,{}]", mask, MaxPrefix);
                }
                return std::nullopt;
            }
        }

        auto dash = s.find('-');
        if (dash != std::string::npos) {
            auto left = s.substr(0, dash);
            auto right = s.substr(dash + 1);
            if (right.empty()) {
                return std::format("empty right-hand side of range in '{}'", s);
            }
            auto left_err = inner_.validate(ValueType{std::string(left)});
            if (left_err) return left_err;
            auto right_err = inner_.validate(ValueType{std::string(right)});
            if (right_err) return right_err;
            return std::nullopt;
        }

        return inner_.validate(value);
    }
};

template <typename T, int MaxPrefix = -1>
requires std::derived_from<T, TypeValidator>
class RangeListValidator : public TypeValidator {
    RangeValidator<T, MaxPrefix> range_;

    static std::string_view trim(std::string_view s) {
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
            s.remove_prefix(1);
        }
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
            s.remove_suffix(1);
        }
        return s;
    }

    std::optional<std::string> validate_range(std::string_view s) const {
        return range_.validate(ValueType{std::string(trim(s))});
    }

public:
    std::optional<std::string> validate(const ValueType& value) const override {
        if (!std::holds_alternative<std::string>(value)) {
            return range_.validate(value);
        }

        const auto raw = trim(std::get<std::string>(value));
        if (!raw.starts_with('[') && !raw.ends_with(']')) {
            return validate_range(raw);
        }
        if (!raw.starts_with('[') || !raw.ends_with(']')) {
            return std::format("malformed range list '{}'", std::get<std::string>(value));
        }

        auto content = raw.substr(1, raw.size() - 2);
        if (trim(content).empty()) {
            return std::string{"empty range list"};
        }

        size_t index = 0;
        size_t item_start = 0;
        while (item_start <= content.size()) {
            auto comma = content.find(',', item_start);
            auto item = comma == std::string_view::npos
                      ? content.substr(item_start)
                      : content.substr(item_start, comma - item_start);
            item = trim(item);
            if (item.empty()) {
                return std::format("empty range at index {}", index);
            }
            if (auto err = validate_range(item)) {
                return std::format("invalid range at index {}: {}", index, *err);
            }
            if (comma == std::string_view::npos) {
                break;
            }
            item_start = comma + 1;
            ++index;
        }

        return std::nullopt;
    }
};

} // namespace packet
