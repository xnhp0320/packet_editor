#include "packet/parser.hpp"
#include "packet/ast.hpp"

#include <gtest/gtest.h>

using namespace packet;

TEST(ParserTest, SingleHeaderNoAttrs) {
    Parser parser("Ether");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());
    EXPECT_EQ(pkt->size(), 1);
    EXPECT_EQ((*pkt)[0].protocol, "Ether");
    EXPECT_TRUE((*pkt)[0].attributes.empty());
}

TEST(ParserTest, SingleHeaderWithAttrs) {
    Parser parser(R"(Ether(dst="ff:ff:ff:ff:ff:ff",src="00:11:22:33:44:55"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());
    EXPECT_EQ(pkt->size(), 1);
    EXPECT_EQ((*pkt)[0].protocol, "Ether");
    EXPECT_EQ((*pkt)[0].attributes.size(), 2);

    auto& a0 = (*pkt)[0].attributes[0];
    EXPECT_EQ(a0.name, "dst");
    ASSERT_TRUE(a0.value.has_value());
    EXPECT_TRUE(std::holds_alternative<std::string>(*a0.value));
    EXPECT_EQ(std::get<std::string>(*a0.value), "ff:ff:ff:ff:ff:ff");

    auto& a1 = (*pkt)[0].attributes[1];
    EXPECT_EQ(a1.name, "src");
    ASSERT_TRUE(a1.value.has_value());
    EXPECT_TRUE(std::holds_alternative<std::string>(*a1.value));
    EXPECT_EQ(std::get<std::string>(*a1.value), "00:11:22:33:44:55");
}

TEST(ParserTest, ScapyStyle) {
    Parser parser(R"(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="192.168.1.1",dst="10.0.0.1")/TCP(dport=80))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());
    EXPECT_EQ(pkt->size(), 3);

    EXPECT_EQ((*pkt)[0].protocol, "Ether");
    EXPECT_EQ((*pkt)[0].attributes.size(), 1);
    EXPECT_EQ((*pkt)[0].attributes[0].name, "dst");
    EXPECT_EQ(std::get<std::string>(*(*pkt)[0].attributes[0].value), "ff:ff:ff:ff:ff:ff");

    EXPECT_EQ((*pkt)[1].protocol, "IP");
    EXPECT_EQ((*pkt)[1].attributes.size(), 2);
    EXPECT_EQ((*pkt)[1].attributes[0].name, "src");
    EXPECT_EQ(std::get<std::string>(*(*pkt)[1].attributes[0].value), "192.168.1.1");
    EXPECT_EQ((*pkt)[1].attributes[1].name, "dst");
    EXPECT_EQ(std::get<std::string>(*(*pkt)[1].attributes[1].value), "10.0.0.1");

    EXPECT_EQ((*pkt)[2].protocol, "TCP");
    EXPECT_EQ((*pkt)[2].attributes.size(), 1);
    EXPECT_EQ((*pkt)[2].attributes[0].name, "dport");
    EXPECT_EQ(std::get<int64_t>(*(*pkt)[2].attributes[0].value), 80);
}

TEST(ParserTest, HexNumber) {
    Parser parser("Raw(len=0xFF)");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());
    EXPECT_EQ(pkt->size(), 1);
    EXPECT_EQ(std::get<int64_t>(*(*pkt)[0].attributes[0].value), 255);
}

TEST(ParserTest, StringEscape) {
    Parser parser(R"(Raw(data="line1\nline2\ttabbed"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());
    EXPECT_EQ(pkt->size(), 1);
    auto val = std::get<std::string>(*(*pkt)[0].attributes[0].value);
    EXPECT_EQ(val, "line1\nline2\ttabbed");
}

TEST(ParserTest, AttributeNameOnly) {
    Parser parser("Flag(URG,ACK,PSH)");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());
    EXPECT_EQ(pkt->size(), 1);
    EXPECT_EQ((*pkt)[0].attributes.size(), 3);
    EXPECT_EQ((*pkt)[0].attributes[0].name, "URG");
    EXPECT_FALSE((*pkt)[0].attributes[0].value.has_value());
    EXPECT_EQ((*pkt)[0].attributes[1].name, "ACK");
    EXPECT_FALSE((*pkt)[0].attributes[1].value.has_value());
    EXPECT_EQ((*pkt)[0].attributes[2].name, "PSH");
    EXPECT_FALSE((*pkt)[0].attributes[2].value.has_value());
}

TEST(ParserTest, EmptyParens) {
    Parser parser("Ether()");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());
    EXPECT_EQ(pkt->size(), 1);
    EXPECT_EQ((*pkt)[0].protocol, "Ether");
    EXPECT_TRUE((*pkt)[0].attributes.empty());
}

TEST(ParserTest, InvalidInput) {
    Parser parser(R"(Ether(dst="unclosed)");
    auto pkt = parser.parse();
    EXPECT_FALSE(pkt.has_value());
    EXPECT_FALSE(parser.last_error().empty());
}

TEST(ParserTest, OperatorSlash) {
    Header ether{"Ether", {Attribute{"dst", std::string("ff:ff:ff:ff:ff:ff")}}};
    Header ip{"IP", {Attribute{"src", std::string("192.168.1.1")}}};
    auto pkt = ether / ip;
    EXPECT_EQ(pkt.size(), 2);
    EXPECT_EQ(pkt[0].protocol, "Ether");
    EXPECT_EQ(pkt[1].protocol, "IP");

    Header tcp{"TCP", {Attribute{"dport", int64_t(80)}}};
    auto pkt2 = pkt / tcp;
    EXPECT_EQ(pkt2.size(), 3);
    EXPECT_EQ(pkt2[2].protocol, "TCP");
    EXPECT_EQ(std::get<int64_t>(*pkt2[2].attributes[0].value), 80);
}
