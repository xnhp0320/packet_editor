#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace packet {

enum class TokenType {
    Identifier,
    StringLiteral,
    IntegerLiteral,
    Equal,
    LeftParen,
    RightParen,
    Comma,
    Slash,
    EndOfFile,
};

struct Token {
    TokenType type;
    std::string_view lexeme;
    size_t position;
};

class Lexer {
public:
    explicit Lexer(std::string_view source);

    std::optional<Token> next();
    Token peek() const;
    std::string last_error() const;

private:
    std::string_view source_;
    size_t pos_ = 0;
    Token current_;
    std::string error_;

    void skip_whitespace();
    std::optional<Token> lex_identifier();
    std::optional<Token> lex_string();
    std::optional<Token> lex_number();
    std::optional<Token> lex_symbol();
    static bool is_identifier_start(char c);
    static bool is_identifier_continue(char c);
    static bool is_digit(char c);
    static bool is_hex_digit(char c);
};

} // namespace packet
