#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace packet {

using ValueType = std::variant<std::string, int64_t>;

struct Expression;
using AttributeValue = std::shared_ptr<Expression>;

struct Attribute {
    std::string name;
    std::optional<AttributeValue> value;

    Attribute(std::string n, std::optional<AttributeValue> v = std::nullopt)
        : name(std::move(n))
        , value(std::move(v))
    {
    }

    Attribute(std::string n, std::string v);
    Attribute(std::string n, const char* v);
    Attribute(std::string n, int64_t v);
};

struct Header {
    std::string protocol;
    std::vector<Attribute> attributes;
};

using Packet = std::vector<Header>;

struct StringExpression {
    std::string value;
};

struct IntegerExpression {
    int64_t value;
};

struct PacketExpression {
    Packet value;
};

struct Expression {
    using Variant = std::variant<StringExpression, IntegerExpression, PacketExpression>;

    Variant value;

    Expression(StringExpression expr)
        : value(std::move(expr))
    {
    }

    Expression(IntegerExpression expr)
        : value(expr)
    {
    }

    Expression(PacketExpression expr)
        : value(std::move(expr))
    {
    }
};

using ExpressionValue = std::variant<std::string, int64_t, Packet>;

struct Variable {
    std::string name;
    Expression expression;
};

struct Program {
    std::vector<Variable> variables;
};

inline AttributeValue make_attribute_value(Expression expression) {
    return std::make_shared<Expression>(std::move(expression));
}

inline Attribute::Attribute(std::string n, std::string v)
    : Attribute(std::move(n), make_attribute_value(StringExpression{std::move(v)}))
{
}

inline Attribute::Attribute(std::string n, const char* v)
    : Attribute(std::move(n), std::string{v})
{
}

inline Attribute::Attribute(std::string n, int64_t v)
    : Attribute(std::move(n), make_attribute_value(IntegerExpression{v}))
{
}

inline ExpressionValue evaluate(const Expression& expression) {
    return std::visit([](const auto& expr) -> ExpressionValue {
        return expr.value;
    }, expression.value);
}

inline Packet operator/(Header h1, Header h2) {
    Packet p;
    p.push_back(std::move(h1));
    p.push_back(std::move(h2));
    return p;
}

inline Packet operator/(Packet p, Header h) {
    p.push_back(std::move(h));
    return p;
}

} // namespace packet
