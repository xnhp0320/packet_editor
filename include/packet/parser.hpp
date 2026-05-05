#pragma once

#include "packet/ast.hpp"
#include "packet/lexer.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace packet {

class Parser {
public:
    explicit Parser(std::string_view input);

    std::optional<Program> parse();
    std::optional<Packet> parse_packet();
    std::optional<Expression> parse_expression();
    std::optional<Variable> parse_variable();
    std::optional<Program> parse_program();
    std::string last_error() const;

private:
    Lexer lexer_;
    std::string error_;

    bool consume(TokenType expected);
    std::optional<PacketExpression> parse_packet_expression();
    std::optional<Header> parse_header();
    std::optional<Attribute> parse_attribute();
    std::optional<ValueType> parse_value();
    std::optional<ValueType> parse_string_value(std::string_view raw);
    std::optional<ValueType> parse_number_value(std::string_view raw);
};

} // namespace packet
