#include "packet/parser.hpp"

#include <charconv>
#include <cstdint>
#include <system_error>
#include <type_traits>
#include <utility>

namespace packet {

Parser::Parser(std::string_view input)
    : lexer_(input)
{
    lexer_.next();
}

std::string Parser::last_error() const {
    if (!error_.empty()) {
        return error_;
    }
    return lexer_.last_error();
}

bool Parser::consume(TokenType expected) {
    if (lexer_.peek().type == expected) {
        lexer_.next();
        return true;
    }
    error_ = "expected token type ";
    error_ += std::to_string(static_cast<int>(expected));
    error_ += " but got ";
    error_ += std::to_string(static_cast<int>(lexer_.peek().type));
    return false;
}

std::optional<ValueType> Parser::parse_string_value(std::string_view raw) {
    auto content = raw.substr(1, raw.size() - 2);
    std::string result;
    for (size_t i = 0; i < content.size(); ++i) {
        if (content[i] == '\\') {
            if (i + 1 >= content.size()) {
                return std::nullopt;
            }
            switch (content[i + 1]) {
                case 'n':  result += '\n'; break;
                case 't':  result += '\t'; break;
                case 'r':  result += '\r'; break;
                case '\\': result += '\\'; break;
                case '"':  result += '"'; break;
                case '0':  result += '\0'; break;
                case 'x':
                case 'X': {
                    if (i + 3 >= content.size()) {
                        return std::nullopt;
                    }
                    char high = content[i + 2];
                    char low  = content[i + 3];
                    auto hex_high = high >= '0' && high <= '9' ? high - '0'
                                  : high >= 'a' && high <= 'f' ? high - 'a' + 10
                                  : high >= 'A' && high <= 'F' ? high - 'A' + 10
                                  : -1;
                    auto hex_low  = low >= '0' && low <= '9' ? low - '0'
                                  : low >= 'a' && low <= 'f' ? low - 'a' + 10
                                  : low >= 'A' && low <= 'F' ? low - 'A' + 10
                                  : -1;
                    if (hex_high < 0 || hex_low < 0) {
                        return std::nullopt;
                    }
                    result += static_cast<char>((hex_high << 4) | hex_low);
                    i += 3;
                    break;
                }
                default:
                    return std::nullopt;
            }
            ++i;
        } else {
            result += content[i];
        }
    }
    return ValueType{std::move(result)};
}

std::optional<ValueType> Parser::parse_number_value(std::string_view raw) {
    int64_t value = 0;
    int base = 10;
    auto num = raw;
    bool negative = false;
    if (num.starts_with('-')) {
        negative = true;
        num = num.substr(1);
    }
    if (num.starts_with("0x") || num.starts_with("0X")) {
        base = 16;
        num = num.substr(2);
    }
    auto [ptr, ec] = std::from_chars(num.data(), num.data() + num.size(), value, base);
    if (ec != std::errc{}) {
        return std::nullopt;
    }
    if (negative) {
        value = -value;
    }
    return ValueType{value};
}

std::optional<Attribute> Parser::parse_attribute() {
    Token name_tok = lexer_.peek();
    if (name_tok.type != TokenType::Identifier) {
        return std::nullopt;
    }
    std::string name(name_tok.lexeme);
    lexer_.next();

    Attribute attr{std::move(name), std::nullopt};

    if (lexer_.peek().type == TokenType::Equal) {
        lexer_.next();

        Token val_tok = lexer_.peek();
        if (val_tok.type == TokenType::StringLiteral) {
            lexer_.next();
            auto val = parse_string_value(val_tok.lexeme);
            if (!val) {
                error_ = "invalid string escape sequence";
                return std::nullopt;
            }
            attr.value = std::move(val);
        } else if (val_tok.type == TokenType::IntegerLiteral) {
            lexer_.next();
            auto val = parse_number_value(val_tok.lexeme);
            if (!val) {
                error_ = "invalid integer literal";
                return std::nullopt;
            }
            attr.value = std::move(val);
        } else {
            error_ = "expected string or integer value";
            return std::nullopt;
        }
    }

    return attr;
}

std::optional<ValueType> Parser::parse_value() {
    Token val_tok = lexer_.peek();
    if (val_tok.type == TokenType::StringLiteral) {
        lexer_.next();
        auto val = parse_string_value(val_tok.lexeme);
        if (!val) {
            error_ = "invalid string escape sequence";
            return std::nullopt;
        }
        return val;
    }

    if (val_tok.type == TokenType::IntegerLiteral) {
        lexer_.next();
        auto val = parse_number_value(val_tok.lexeme);
        if (!val) {
            error_ = "invalid integer literal";
            return std::nullopt;
        }
        return val;
    }

    error_ = "expected string or integer value";
    return std::nullopt;
}

std::optional<Header> Parser::parse_header() {
    Token proto_tok = lexer_.peek();
    if (proto_tok.type != TokenType::Identifier) {
        return std::nullopt;
    }
    std::string protocol(proto_tok.lexeme);
    lexer_.next();

    if (lexer_.peek().type != TokenType::LeftParen) {
        return Header{std::move(protocol), {}};
    }
    lexer_.next();

    std::vector<Attribute> attrs;
    if (lexer_.peek().type != TokenType::RightParen) {
        do {
            auto attr = parse_attribute();
            if (!attr) {
                return std::nullopt;
            }
            attrs.push_back(std::move(*attr));

            if (lexer_.peek().type == TokenType::Comma) {
                lexer_.next();
            } else {
                break;
            }
        } while (true);
    }

    if (!consume(TokenType::RightParen)) {
        return std::nullopt;
    }

    return Header{std::move(protocol), std::move(attrs)};
}

std::optional<PacketExpression> Parser::parse_packet_expression() {
    Packet result;
    auto header = parse_header();
    if (!header) {
        return std::nullopt;
    }
    result.push_back(std::move(*header));

    while (lexer_.peek().type == TokenType::Slash) {
        lexer_.next();
        auto next_header = parse_header();
        if (!next_header) {
            return std::nullopt;
        }
        result.push_back(std::move(*next_header));
    }

    return PacketExpression{std::move(result)};
}

std::optional<Expression> Parser::parse_expression() {
    if (lexer_.peek().type == TokenType::StringLiteral ||
        lexer_.peek().type == TokenType::IntegerLiteral) {
        auto value = parse_value();
        if (!value) {
            return std::nullopt;
        }
        return std::visit([](auto&& v) -> Expression {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, std::string>) {
                return StringExpression{std::move(v)};
            } else {
                return IntegerExpression{v};
            }
        }, std::move(*value));
    }

    auto packet = parse_packet_expression();
    if (!packet) {
        return std::nullopt;
    }
    return std::move(*packet);
}

std::optional<Variable> Parser::parse_variable() {
    Token name_tok = lexer_.peek();
    if (name_tok.type != TokenType::Identifier) {
        error_ = "expected variable name";
        return std::nullopt;
    }

    std::string name(name_tok.lexeme);
    lexer_.next();

    if (!consume(TokenType::Colon)) {
        return std::nullopt;
    }

    auto expression = parse_expression();
    if (!expression) {
        return std::nullopt;
    }

    return Variable{std::move(name), std::move(*expression)};
}

std::optional<Program> Parser::parse_program() {
    Program program;

    while (lexer_.peek().type != TokenType::EndOfFile) {
        auto variable = parse_variable();
        if (!variable) {
            return std::nullopt;
        }
        program.variables.push_back(std::move(*variable));
    }

    return program;
}

std::optional<Packet> Parser::parse_packet() {
    auto expression = parse_expression();
    if (!expression) {
        return std::nullopt;
    }

    if (lexer_.peek().type != TokenType::EndOfFile) {
        error_ = "unexpected token after packet";
        return std::nullopt;
    }

    auto value = evaluate(*expression);
    if (!std::holds_alternative<Packet>(value)) {
        error_ = "expected packet expression";
        return std::nullopt;
    }

    return std::get<Packet>(std::move(value));
}

std::optional<Program> Parser::parse() {
    return parse_program();
}

} // namespace packet
