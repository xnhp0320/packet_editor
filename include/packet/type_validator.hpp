#pragma once

#include "packet/ast.hpp"

#include <cctype>
#include <concepts>
#include <cstdint>
#include <format>
#include <memory>
#include <optional>
#include <string>

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

} // namespace packet
