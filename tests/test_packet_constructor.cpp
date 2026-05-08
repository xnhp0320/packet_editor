#include "packet/packet_constructor.hpp"
#include "packet/parser.hpp"
#include "packet/registry.hpp"
#include "packet/value.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using namespace packet;

namespace {

Packet parse_packet(std::string_view input) {
    Parser parser(input);
    auto packet = parser.parse_packet();
    EXPECT_TRUE(packet.has_value()) << parser.last_error();
    return std::move(*packet);
}

PacketConstructorBuilder::Result build(std::string_view input) {
    Registry registry;
    PacketConstructorBuilder builder{registry};
    return builder.build(parse_packet(input));
}

PacketConstructorBuilder::Result build(std::string_view input, const Registry& registry) {
    PacketConstructorBuilder builder{registry};
    return builder.build(parse_packet(input));
}

const FieldConstructor& field(const HeaderConstructor& header, std::string_view name) {
    auto it = std::ranges::find_if(header.fields, [name](const FieldConstructor& field) {
        return field.name == name;
    });
    EXPECT_NE(it, header.fields.end());
    return *it;
}

} // namespace

TEST(PacketConstructorTest, BuildsDefaultsAndOffsets) {
    auto result = build("Ether()/IP()/TCP()");

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());
    ASSERT_EQ(result.packet->size(), 3);

    EXPECT_EQ((*result.packet)[0].protocol, "Ether");
    EXPECT_EQ((*result.packet)[0].offset, 0);
    EXPECT_EQ((*result.packet)[0].fields.size(), 3);

    EXPECT_EQ((*result.packet)[1].protocol, "IP");
    EXPECT_EQ((*result.packet)[1].offset, 14);
    EXPECT_EQ((*result.packet)[1].fields.size(), 12);
    EXPECT_EQ(std::get<uint64_t>(field((*result.packet)[1], "version").value), 4);
    EXPECT_EQ(std::get<uint64_t>(field((*result.packet)[1], "ihl").value), 5);
    EXPECT_EQ(std::get<uint64_t>(field((*result.packet)[1], "ttl").value), 64);
    EXPECT_FALSE(field((*result.packet)[1], "ttl").explicitly_set);

    EXPECT_EQ((*result.packet)[2].protocol, "TCP");
    EXPECT_EQ((*result.packet)[2].offset, 34);
    EXPECT_EQ(std::get<uint64_t>(field((*result.packet)[2], "dataofs").value), 5);
}

TEST(PacketConstructorTest, UserValuesOverrideDefaultsAndKeepRegistryOrder) {
    auto result = build(R"(IP(dst="10.0.0.1",ttl=32,src="192.168.1.1"))");

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());
    ASSERT_EQ(result.packet->size(), 1);

    const auto& ip = (*result.packet)[0];
    ASSERT_GE(ip.fields.size(), 12);
    EXPECT_EQ(ip.fields[0].name, "version");
    EXPECT_EQ(ip.fields[1].name, "ihl");
    EXPECT_EQ(ip.fields[8].name, "proto");
    EXPECT_EQ(ip.fields[9].name, "src");
    EXPECT_EQ(ip.fields[10].name, "dst");

    EXPECT_EQ(std::get<uint64_t>(field(ip, "ttl").value), 32);
    EXPECT_TRUE(field(ip, "ttl").explicitly_set);

    const auto& src_ranges = std::get<std::vector<IPv4Range>>(field(ip, "src").value);
    ASSERT_EQ(src_ranges.size(), 1);
    EXPECT_EQ(src_ranges[0].first.to_string(), "192.168.1.1");
    EXPECT_EQ(src_ranges[0].last.to_string(), "192.168.1.1");
    EXPECT_TRUE(field(ip, "src").explicitly_set);
}

TEST(PacketConstructorTest, NormalizesMacAndRanges) {
    auto result = build(R"(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="[10.0.0.1, 10.0.0.0/24, 10.0.1.1-10.0.1.255]")/IPv6(src="2001:db8::/126"))");

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());

    const auto& ether = (*result.packet)[0];
    EXPECT_EQ(std::get<MacAddr>(field(ether, "dst").value).to_string(), "ff:ff:ff:ff:ff:ff");

    const auto& ipv4_ranges = std::get<std::vector<IPv4Range>>(field((*result.packet)[1], "src").value);
    ASSERT_EQ(ipv4_ranges.size(), 3);
    EXPECT_EQ(ipv4_ranges[0].first.to_string(), "10.0.0.1");
    EXPECT_EQ(ipv4_ranges[0].last.to_string(), "10.0.0.1");
    EXPECT_EQ(ipv4_ranges[1].first.to_string(), "10.0.0.0");
    EXPECT_EQ(ipv4_ranges[1].last.to_string(), "10.0.0.255");
    EXPECT_EQ(ipv4_ranges[2].first.to_string(), "10.0.1.1");
    EXPECT_EQ(ipv4_ranges[2].last.to_string(), "10.0.1.255");

    const auto& ipv6_ranges = std::get<std::vector<IPv6Range>>(field((*result.packet)[2], "src").value);
    ASSERT_EQ(ipv6_ranges.size(), 1);
    EXPECT_EQ(ipv6_ranges[0].first.to_string(), "2001:0db8:0000:0000:0000:0000:0000:0000");
    EXPECT_EQ(ipv6_ranges[0].last.to_string(), "2001:0db8:0000:0000:0000:0000:0000:0003");
}

TEST(PacketConstructorTest, UnknownHeaderFails) {
    auto result = build("BadHeader()");

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "unknown header: 'BadHeader'");
    EXPECT_FALSE(result.packet.has_value());
}

TEST(PacketConstructorTest, UnknownAttributeFails) {
    auto result = build("Ether(unknown=1)");

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "unknown attribute 'unknown' in header 'Ether'");
}

TEST(PacketConstructorTest, DuplicateAttributeFails) {
    auto result = build("UDP(sport=1,sport=2)");

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "duplicate attribute 'sport' in header 'UDP'");
}

TEST(PacketConstructorTest, NameOnlyAttributeFails) {
    auto result = build("TCP(SYN)");

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "unknown attribute 'SYN' in header 'TCP'");
}

TEST(PacketConstructorTest, KnownNameOnlyAttributeFails) {
    auto result = build("TCP(flags)");

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "attribute 'flags' in header 'TCP' requires a value");
}

TEST(PacketConstructorTest, BitWidthOverflowFails) {
    auto result = build("TCP(dport=65536)");

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_NE(result.errors[0].find("16 bits"), std::string::npos);
}

TEST(PacketConstructorTest, BitRangesDefaultToScalarZero) {
    Registry registry;
    registry.register_header("MyHdr", {{"field", "b16_ranges"}});

    auto result = build("MyHdr()", registry);

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());
    ASSERT_EQ(result.packet->size(), 1);

    const auto& constructed = field((*result.packet)[0], "field");
    EXPECT_EQ(std::get<uint64_t>(constructed.value), 0);
    EXPECT_FALSE(constructed.explicitly_set);
}

TEST(PacketConstructorTest, BitRangesPreserveScalarSyntaxAsUInt64) {
    Registry registry;
    registry.register_header("MyHdr", {
        {"unquoted", "b16_ranges"},
        {"quoted", "b16_ranges"},
    });

    auto result = build(R"(MyHdr(unquoted=1,quoted="2"))", registry);

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());

    const auto& header = (*result.packet)[0];
    EXPECT_EQ(std::get<uint64_t>(field(header, "unquoted").value), 1);
    EXPECT_EQ(std::get<uint64_t>(field(header, "quoted").value), 2);
    EXPECT_TRUE(field(header, "unquoted").explicitly_set);
    EXPECT_TRUE(field(header, "quoted").explicitly_set);
}

TEST(PacketConstructorTest, BitRangesNormalizeRangeSyntax) {
    Registry registry;
    registry.register_header("MyHdr", {
        {"range", "b16_ranges"},
        {"list", "b16_ranges"},
    });

    auto result = build(R"(MyHdr(range="1-2",list="[1, 2-3]"))", registry);

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());

    const auto& header = (*result.packet)[0];
    const auto& range = std::get<std::vector<UIntRange>>(field(header, "range").value);
    ASSERT_EQ(range.size(), 1);
    EXPECT_EQ(range[0].first, 1);
    EXPECT_EQ(range[0].last, 2);

    const auto& list = std::get<std::vector<UIntRange>>(field(header, "list").value);
    ASSERT_EQ(list.size(), 2);
    EXPECT_EQ(list[0].first, 1);
    EXPECT_EQ(list[0].last, 1);
    EXPECT_EQ(list[1].first, 2);
    EXPECT_EQ(list[1].last, 3);
}
