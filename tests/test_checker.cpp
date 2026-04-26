#include "packet/checker.hpp"
#include "packet/parser.hpp"

#include <gtest/gtest.h>

using namespace packet;

TEST(CheckerTest, AllKnownHeaders) {
    Parser parser("Ether()/IP()/IPv6()/TCP()/UDP()/ICMP()/VXLAN()");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
    EXPECT_TRUE(result.warnings.empty());
}

TEST(CheckerTest, UnknownHeader) {
    Parser parser("Ether()/BadProtocol()");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
    EXPECT_TRUE(result.errors[0].find("BadProtocol") != std::string::npos);
}

TEST(CheckerTest, KnownAttrsNoWarnings) {
    Parser parser(R"(Ether(dst="ff:ff:ff:ff:ff:ff",src="00:11:22:33:44:55"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.warnings.empty());
}

TEST(CheckerTest, UnknownAttributeWarning) {
    Parser parser(R"(Ether(dst="ff:ff:ff:ff:ff:ff",foobar=42))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_EQ(result.warnings.size(), 1);
    EXPECT_TRUE(result.warnings[0].find("foobar") != std::string::npos);
    EXPECT_TRUE(result.warnings[0].find("Ether") != std::string::npos);
}

TEST(CheckerTest, MixedErrorsAndWarnings) {
    Parser parser(R"(Ether(unknown_attr=1)/BadProto(dport=80))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.warnings.size(), 1);
}

TEST(CheckerTest, ScapyStyleSemanticCheck) {
    Parser parser(R"(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="192.168.1.1",dst="10.0.0.1")/TCP(dport=80,sport=1234))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
    EXPECT_TRUE(result.warnings.empty());
}

TEST(CheckerTest, TcpAllAttrs) {
    Parser parser(R"(TCP(sport=1,dport=2,seq=3,ack=4,dataofs=5,reserved=6,flags=7,window=8,chksum=9,urgptr=10))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.warnings.empty());
}

TEST(CheckerTest, UdpAttrs) {
    Parser parser(R"(UDP(sport=53,dport=53,len=128,chksum=0))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.warnings.empty());
}

TEST(CheckerTest, IcmpAttrs) {
    Parser parser(R"(ICMP(type=8,code=0,chksum=0xffff,id=1,seq=1))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.warnings.empty());
}

TEST(CheckerTest, VxlanAttrs) {
    Parser parser(R"(VXLAN(flags=0x08,reserved=0,vni=100,reserved2=0))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.warnings.empty());
}

TEST(CheckerTest, CustomHeaderRegistration) {
    Parser parser("MyProto(field1=1,field2=2)");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    checker.register_header("MyProto", {"field1", "field2", "field3"});

    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
    EXPECT_TRUE(result.warnings.empty());
}

TEST(CheckerTest, CustomHeaderUnknownAttr) {
    Parser parser("MyProto(bad_field=1)");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    checker.register_header("MyProto", {"field1", "field2"});

    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_EQ(result.warnings.size(), 1);
}

TEST(CheckerTest, ValidateOrExitDoesNotExitOnValid) {
    Parser parser("Ether()/IP()");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    checker.validate_or_exit(*pkt);
    SUCCEED();
}
