#pragma once

#include "packet/ast.hpp"

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

} // namespace packet
