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
    checker.register_header("MyProto", {
        {"field1", std::nullopt},
        {"field2", std::nullopt},
        {"field3", std::nullopt},
    });

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
    checker.register_header("MyProto", {
        {"field1", std::nullopt},
        {"field2", std::nullopt},
    });

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

TEST(CheckerTest, ValidMacAddr) {
    Parser parser(R"(Ether(dst="ff:ff:ff:ff:ff:ff",src="00:11:22:33:44:55"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
}

TEST(CheckerTest, InvalidMacAddrTooShort) {
    Parser parser(R"(Ether(dst="ff:ff:ff"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
    EXPECT_TRUE(result.errors[0].find("dst") != std::string::npos);
}

TEST(CheckerTest, InvalidMacAddrNonHex) {
    Parser parser(R"(Ether(dst="gg:ff:ff:ff:ff:ff"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
    EXPECT_TRUE(result.errors[0].find("dst") != std::string::npos);
}

TEST(CheckerTest, InvalidMacAddrMissingColon) {
    Parser parser(R"(Ether(dst="ffffff:ff:ff:ff:ff"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
}

TEST(CheckerTest, ValidIPv4Addr) {
    Parser parser(R"(IP(src="192.168.1.1",dst="10.0.0.1"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
}

TEST(CheckerTest, InvalidIPv4BadOctet) {
    Parser parser(R"(IP(src="256.0.0.1"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
    EXPECT_TRUE(result.errors[0].find("src") != std::string::npos);
}

TEST(CheckerTest, InvalidIPv4TooFewDots) {
    Parser parser(R"(IP(src="192.168.1"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
}

TEST(CheckerTest, InvalidIPv4NonNumeric) {
    Parser parser(R"(IP(src="abc.def.ghi.jkl"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
}

TEST(CheckerTest, ValidIPv6Addr) {
    Parser parser(R"(IPv6(src="2001:db8::1",dst="fe80::1"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
}

TEST(CheckerTest, ValidIPv6FullAddr) {
    Parser parser(R"(IPv6(src="2001:0db8:0000:0000:0000:ff00:0042:8329"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
}

TEST(CheckerTest, ValidIPv6Loopback) {
    Parser parser(R"(IPv6(src="::1"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
}

TEST(CheckerTest, InvalidIPv6DoubleDoubleColon) {
    Parser parser(R"(IPv6(src="2001::10::1"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
}

TEST(CheckerTest, InvalidIPv6BadHexGroup) {
    Parser parser(R"(IPv6(src="2001:xyz1::1"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
}

TEST(CheckerTest, InvalidIPv6TooManyGroups) {
    Parser parser(R"(IPv6(src="1:2:3:4::5:6:7:8:9"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
}

TEST(CheckerTest, MacAddrMustBeString) {
    Parser parser(R"(Ether(dst=123456))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(result.errors[0].find("string") != std::string::npos);
}

TEST(CheckerTest, IPBothSrcAndDstValid) {
    Parser parser(R"(IP(src="1.2.3.4",dst="5.6.7.8"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
}

TEST(CheckerTest, UnknownAttrSkippedNoFormatError) {
    Parser parser(R"(Ether(unk="not-a-mac-addr-but-unknown-attr"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_EQ(result.warnings.size(), 1);
    EXPECT_TRUE(result.errors.empty());
}

TEST(CheckerTest, CustomTypeRegistration) {
    Parser parser("MyProto(addr=\"hello\")");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    class AlwaysFails : public TypeValidator {
    public:
        std::optional<std::string> validate(const ValueType&) const override {
            return std::string{"always fails"};
        }
    };

    Checker checker;
    checker.register_type("always_fails", std::make_unique<AlwaysFails>());
    checker.register_header("MyProto", {{"addr", "always_fails"}});

    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
    EXPECT_TRUE(result.errors[0].find("always fails") != std::string::npos);
}

TEST(CheckerTest, BitFieldInRange) {
    Parser parser("UDP(sport=53,dport=53,len=128,chksum=0)");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
}

TEST(CheckerTest, BitFieldOutOfRange) {
    Parser parser("TCP(dport=65536)");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
    EXPECT_TRUE(result.errors[0].find("dport") != std::string::npos);
    EXPECT_TRUE(result.errors[0].find("16") != std::string::npos);
}

TEST(CheckerTest, BitFieldNegative) {
    Parser parser("TCP(sport=-1)");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
}

TEST(CheckerTest, BitFieldAtMax) {
    Parser parser("TCP(sport=65535,dport=65535)");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
}

TEST(CheckerTest, BitFieldB1Zero) {
    Parser parser("ICMP(type=0)");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
}

TEST(CheckerTest, BitFieldB64) {
    Parser parser("MyHdr(field=9223372036854775807)");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    checker.register_header("MyHdr", {{"field", "b64"}});

    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
}

TEST(CheckerTest, BitFieldMustBeInteger) {
    Parser parser(R"(TCP(dport="not-a-number"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(result.errors[0].find("expected integer") != std::string::npos);
}

TEST(CheckerTest, BitFieldB4Max) {
    Parser parser("IP(version=15,ihl=15)");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
}

TEST(CheckerTest, BitFieldB4Overflow) {
    Parser parser("IP(version=16,ihl=16)");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 2);
}

TEST(CheckerTest, BitFieldB20AtMax) {
    Parser parser("IPv6(fl=1048575)");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
}

TEST(CheckerTest, BitFieldB20Overflow) {
    Parser parser("IPv6(fl=1048576)");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
    EXPECT_TRUE(result.errors[0].find("20") != std::string::npos);
}

TEST(CheckerTest, IPv4SingleAddressInRangeType) {
    Parser parser(R"(IP(src="192.168.1.1",dst="10.0.0.1"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
}

TEST(CheckerTest, IPv4CIDR) {
    Parser parser(R"(IP(src="10.0.0.0/24"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
}

TEST(CheckerTest, IPv4CIDRMaskZero) {
    Parser parser(R"(IP(src="0.0.0.0/0"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
}

TEST(CheckerTest, IPv4CIDRMask32) {
    Parser parser(R"(IP(src="1.2.3.4/32"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
}

TEST(CheckerTest, IPv4CIDRMaskOutOfRange) {
    Parser parser(R"(IP(src="10.0.0.0/33"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
    EXPECT_TRUE(result.errors[0].find("33") != std::string::npos);
}

TEST(CheckerTest, IPv4CIDRBadPrefix) {
    Parser parser(R"(IP(src="256.0.0.0/24"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
}

TEST(CheckerTest, IPv4CIDREmptyMask) {
    Parser parser(R"(IP(src="10.0.0.0/"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
}

TEST(CheckerTest, IPv4CIDRNonNumericMask) {
    Parser parser(R"(IP(src="10.0.0.0/abc"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
}

TEST(CheckerTest, IPv4Range) {
    Parser parser(R"(IP(src="10.0.0.1-10.0.0.255"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
}

TEST(CheckerTest, IPv4RangeBadLeft) {
    Parser parser(R"(IP(src="256.0.0.1-10.0.0.255"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
}

TEST(CheckerTest, IPv4RangeBadRight) {
    Parser parser(R"(IP(src="10.0.0.1-10.0.0.256"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
}

TEST(CheckerTest, IPv4RangeEmptyRight) {
    Parser parser(R"(IP(src="10.0.0.1-"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
}

TEST(CheckerTest, IPv6CIDR) {
    Parser parser(R"(IPv6(src="2001:db8::/48"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
}

TEST(CheckerTest, IPv6CIDRMask128) {
    Parser parser(R"(IPv6(src="::1/128"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
}

TEST(CheckerTest, IPv6CIDRMaskOutOfRange) {
    Parser parser(R"(IPv6(src="2001:db8::/129"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.errors.size(), 1);
}

TEST(CheckerTest, IPv6Range) {
    Parser parser(R"(IPv6(src="2001:db8::1-2001:db8::ff"))");
    auto pkt = parser.parse();
    ASSERT_TRUE(pkt.has_value());

    Checker checker;
    auto result = checker.check(*pkt);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
}
