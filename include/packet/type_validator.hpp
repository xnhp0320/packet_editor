#pragma once

#include "packet/ast.hpp"
#include "packet/util.hpp"

#include <cstdint>
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

class IPv4RangeValidator : public TypeValidator {
public:
    std::optional<std::string> validate(const ValueType& value) const override;
};

class IPv6RangeValidator : public TypeValidator {
public:
    std::optional<std::string> validate(const ValueType& value) const override;
};

class IPv4RangeListValidator : public TypeValidator {
public:
    std::optional<std::string> validate(const ValueType& value) const override;
};

class IPv6RangeListValidator : public TypeValidator {
public:
    std::optional<std::string> validate(const ValueType& value) const override;
};

template <size_t N>
requires (N >= 1 && N <= 64)
class BitsValidator : public TypeValidator {
public:
    std::optional<std::string> validate(const ValueType& value) const override {
        return validate_bit_value(value, N);
    }
};

template <size_t N>
requires (N >= 1 && N <= 64)
class BitRangeListValidator : public TypeValidator {
public:
    std::optional<std::string> validate(const ValueType& value) const override {
        return validate_bit_range_value(value, N);
    }
};

} // namespace packet
