#include "packet/lexer.hpp"

#include <cctype>
#include <charconv>
#include <system_error>

namespace packet {

Lexer::Lexer(std::string_view source)
    : source_(source)
    , pos_(0)
    , current_{TokenType::EndOfFile, source_.substr(source_.size()), source_.size()}
{
}

Token Lexer::peek() const {
    return current_;
}

std::string Lexer::last_error() const {
    return error_;
}

bool Lexer::is_identifier_start(char c) {
    return std::isalpha(static_cast<unsigned char>(c)) || c == '_';
}

bool Lexer::is_identifier_continue(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

bool Lexer::is_digit(char c) {
    return std::isdigit(static_cast<unsigned char>(c));
}

bool Lexer::is_hex_digit(char c) {
    return std::isxdigit(static_cast<unsigned char>(c));
}

void Lexer::skip_whitespace() {
    while (pos_ < source_.size()) {
        char c = source_[pos_];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            ++pos_;
        } else {
            break;
        }
    }
}

std::optional<Token> Lexer::lex_identifier() {
    size_t start = pos_;
    while (pos_ < source_.size() && is_identifier_continue(source_[pos_])) {
        ++pos_;
    }
    return Token{TokenType::Identifier, source_.substr(start, pos_ - start), start};
}

std::optional<Token> Lexer::lex_string() {
    size_t start = pos_;
    ++pos_;
    while (pos_ < source_.size()) {
        char c = source_[pos_];
        if (c == '"') {
            ++pos_;
            return Token{TokenType::StringLiteral, source_.substr(start, pos_ - start), start};
        }
        if (c == '\\' && pos_ + 1 < source_.size()) {
            pos_ += 2;
        } else {
            ++pos_;
        }
    }
    error_ = "unterminated string literal";
    return std::nullopt;
}

std::optional<Token> Lexer::lex_number() {
    size_t start = pos_;
    if (pos_ < source_.size() && source_[pos_] == '0') {
        ++pos_;
        if (pos_ < source_.size() && (source_[pos_] == 'x' || source_[pos_] == 'X')) {
            ++pos_;
            if (pos_ >= source_.size() || !is_hex_digit(source_[pos_])) {
                error_ = "invalid hex literal";
                return std::nullopt;
            }
            while (pos_ < source_.size() && is_hex_digit(source_[pos_])) {
                ++pos_;
            }
            return Token{TokenType::IntegerLiteral, source_.substr(start, pos_ - start), start};
        }
    }
    while (pos_ < source_.size() && is_digit(source_[pos_])) {
        ++pos_;
    }
    if (pos_ == start) {
        return std::nullopt;
    }
    return Token{TokenType::IntegerLiteral, source_.substr(start, pos_ - start), start};
}

std::optional<Token> Lexer::lex_symbol() {
    size_t start = pos_;
    char c = source_[pos_];
    TokenType type;
    switch (c) {
        case '=': type = TokenType::Equal; break;
        case '(': type = TokenType::LeftParen; break;
        case ')': type = TokenType::RightParen; break;
        case ',': type = TokenType::Comma; break;
        case '/': type = TokenType::Slash; break;
        case ':': type = TokenType::Colon; break;
        default: return std::nullopt;
    }
    ++pos_;
    return Token{type, source_.substr(start, 1), start};
}

std::optional<Token> Lexer::next() {
    skip_whitespace();

    if (pos_ >= source_.size()) {
        current_ = Token{TokenType::EndOfFile, source_.substr(source_.size()), source_.size()};
        return current_;
    }

    char c = source_[pos_];
    std::optional<Token> result;

    if (c == '-' && pos_ + 1 < source_.size() && is_digit(source_[pos_ + 1])) {
        size_t neg_start = pos_;
        ++pos_;
        result = lex_number();
        if (result) {
            result->lexeme = source_.substr(neg_start, pos_ - neg_start);
            result->position = neg_start;
        }
    } else if (c == '"') {
        result = lex_string();
    } else if (is_digit(c)) {
        result = lex_number();
    } else if (is_identifier_start(c)) {
        result = lex_identifier();
    } else {
        result = lex_symbol();
        if (!result) {
            error_ = "unexpected character: ";
            error_ += c;
        }
    }

    if (result) {
        current_ = *result;
    }
    return result;
}

} // namespace packet
