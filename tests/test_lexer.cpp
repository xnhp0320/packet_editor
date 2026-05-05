#include "packet/lexer.hpp"

#include <gtest/gtest.h>

using namespace packet;

TEST(LexerTest, Identifiers) {
    Lexer lexer("Ether IP_Header dst23 _underscore");
    auto t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Identifier);
    EXPECT_EQ(t->lexeme, "Ether");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Identifier);
    EXPECT_EQ(t->lexeme, "IP_Header");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Identifier);
    EXPECT_EQ(t->lexeme, "dst23");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Identifier);
    EXPECT_EQ(t->lexeme, "_underscore");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::EndOfFile);
}

TEST(LexerTest, Symbols) {
    Lexer lexer("= ( ) , / :");
    auto t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Equal);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::LeftParen);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::RightParen);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Comma);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Slash);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Colon);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::EndOfFile);
}

TEST(LexerTest, Strings) {
    Lexer lexer(R"("hello" "world" "")");
    auto t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::StringLiteral);
    EXPECT_EQ(t->lexeme, R"("hello")");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::StringLiteral);
    EXPECT_EQ(t->lexeme, R"("world")");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::StringLiteral);
    EXPECT_EQ(t->lexeme, R"("")");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::EndOfFile);
}

TEST(LexerTest, StringEscape) {
    Lexer lexer(R"("hello\nworld")");
    auto t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::StringLiteral);
    EXPECT_EQ(t->lexeme, R"("hello\nworld")");
}

TEST(LexerTest, Numbers) {
    Lexer lexer("123 0 0xFF 0xab 0x0");
    auto t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::IntegerLiteral);
    EXPECT_EQ(t->lexeme, "123");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::IntegerLiteral);
    EXPECT_EQ(t->lexeme, "0");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::IntegerLiteral);
    EXPECT_EQ(t->lexeme, "0xFF");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::IntegerLiteral);
    EXPECT_EQ(t->lexeme, "0xab");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::IntegerLiteral);
    EXPECT_EQ(t->lexeme, "0x0");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::EndOfFile);
}

TEST(LexerTest, ScapyStyle) {
    Lexer lexer(R"(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="192.168.1.1",dst="10.0.0.1")/TCP(dport=80))");

    auto t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Identifier);
    EXPECT_EQ(t->lexeme, "Ether");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::LeftParen);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Identifier);
    EXPECT_EQ(t->lexeme, "dst");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Equal);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::StringLiteral);
    EXPECT_EQ(t->lexeme, R"("ff:ff:ff:ff:ff:ff")");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::RightParen);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Slash);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Identifier);
    EXPECT_EQ(t->lexeme, "IP");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::LeftParen);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Identifier);
    EXPECT_EQ(t->lexeme, "src");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Equal);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::StringLiteral);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Comma);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Identifier);
    EXPECT_EQ(t->lexeme, "dst");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Equal);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::StringLiteral);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::RightParen);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Slash);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Identifier);
    EXPECT_EQ(t->lexeme, "TCP");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::LeftParen);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Identifier);
    EXPECT_EQ(t->lexeme, "dport");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::Equal);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::IntegerLiteral);
    EXPECT_EQ(t->lexeme, "80");

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::RightParen);

    t = lexer.next();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->type, TokenType::EndOfFile);
}

TEST(LexerTest, UnterminatedString) {
    Lexer lexer("\"hello");
    auto t = lexer.next();
    EXPECT_FALSE(t.has_value());
    EXPECT_EQ(lexer.last_error(), "unterminated string literal");
}
