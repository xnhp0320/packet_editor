#include "packet/packet_constructor.hpp"
#include "packet/parser.hpp"
#include "packet/registry.hpp"
#include "packet/value.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
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

const OptionConstructor& option(const HeaderConstructor& header, std::string_view name) {
    auto it = std::ranges::find_if(header.options, [name](const OptionConstructor& option) {
        return option.name == name;
    });
    EXPECT_NE(it, header.options.end());
    return *it;
}

const ConstructorValue& scalar_option(const HeaderConstructor& header, std::string_view name) {
    const auto& value = option(header, name).value;
    EXPECT_TRUE(std::holds_alternative<ConstructorValue>(value));
    return std::get<ConstructorValue>(value);
}

const PacketConstructor& packet_option(const HeaderConstructor& header, std::string_view name) {
    const auto& value = option(header, name).value;
    EXPECT_TRUE(std::holds_alternative<std::shared_ptr<PacketConstructor>>(value));
    return *std::get<std::shared_ptr<PacketConstructor>>(value);
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
    EXPECT_EQ(ip.fields[9].name, "chksum");
    EXPECT_EQ(ip.fields[10].name, "src");
    EXPECT_EQ(ip.fields[11].name, "dst");

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

TEST(PacketConstructorTest, VlanOffsetsAndFields) {
    auto result = build("Ether()/VLAN()/IP()");

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());
    ASSERT_EQ(result.packet->size(), 3);

    const auto& ether = (*result.packet)[0];
    const auto& vlan = (*result.packet)[1];
    const auto& ip = (*result.packet)[2];

    EXPECT_EQ(ether.protocol, "Ether");
    EXPECT_EQ(ether.offset, 0);
    EXPECT_EQ(vlan.protocol, "VLAN");
    EXPECT_EQ(vlan.offset, 14);
    EXPECT_EQ(ip.protocol, "IP");
    EXPECT_EQ(ip.offset, 18);

    ASSERT_EQ(vlan.fields.size(), 4);
    EXPECT_EQ(vlan.fields[0].name, "prio");
    EXPECT_EQ(vlan.fields[1].name, "dei");
    EXPECT_EQ(vlan.fields[2].name, "vlan");
    EXPECT_EQ(vlan.fields[3].name, "type");
}

TEST(PacketConstructorTest, InfersAdjacentProtocolFields) {
    auto result = build("Ether()/VLAN()/IP()/UDP()");

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());
    ASSERT_EQ(result.packet->size(), 4);
    EXPECT_TRUE(result.warnings.empty());

    const auto& ether = (*result.packet)[0];
    const auto& vlan = (*result.packet)[1];
    const auto& ip = (*result.packet)[2];

    EXPECT_EQ(std::get<uint64_t>(field(ether, "type").value), 0x8100);
    EXPECT_FALSE(field(ether, "type").explicitly_set);
    EXPECT_EQ(std::get<uint64_t>(field(vlan, "type").value), 0x0800);
    EXPECT_FALSE(field(vlan, "type").explicitly_set);
    EXPECT_EQ(std::get<uint64_t>(field(ip, "proto").value), 17);
    EXPECT_FALSE(field(ip, "proto").explicitly_set);
}

TEST(PacketConstructorTest, InfersIpv6NextHeader) {
    auto result = build("Ether()/IPv6()/TCP()");

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());
    ASSERT_EQ(result.packet->size(), 3);

    const auto& ether = (*result.packet)[0];
    const auto& ipv6 = (*result.packet)[1];

    EXPECT_EQ(std::get<uint64_t>(field(ether, "type").value), 0x86dd);
    EXPECT_FALSE(field(ether, "type").explicitly_set);
    EXPECT_EQ(std::get<uint64_t>(field(ipv6, "nh").value), 6);
    EXPECT_FALSE(field(ipv6, "nh").explicitly_set);
}

TEST(PacketConstructorTest, ExplicitProtocolFieldOverridesInferenceWithWarning) {
    auto result = build("Ether(type=0x86dd)/IP()");

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());
    ASSERT_EQ(result.packet->size(), 2);
    ASSERT_EQ(result.warnings.size(), 1);
    EXPECT_EQ(result.warnings[0], "explicit 'Ether.type' overrides inference from next header 'IP'");

    const auto& ether = (*result.packet)[0];
    EXPECT_EQ(std::get<uint64_t>(field(ether, "type").value), 0x86dd);
    EXPECT_TRUE(field(ether, "type").explicitly_set);
}

TEST(PacketConstructorTest, MatchingExplicitProtocolFieldDoesNotWarn) {
    auto result = build("Ether(type=0x0800)/IP()");

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());
    EXPECT_TRUE(result.warnings.empty());

    const auto& ether = (*result.packet)[0];
    EXPECT_EQ(std::get<uint64_t>(field(ether, "type").value), 0x0800);
    EXPECT_TRUE(field(ether, "type").explicitly_set);
}

TEST(PacketConstructorTest, CustomInferenceRuleUsesAdjacentHeaders) {
    Registry registry;
    registry.register_header("Outer", {{"type", "b16"}});
    registry.register_header("Inner", {{"field", "b8"}});
    registry.register_inference_rule("Outer", "Inner", "type", ConstructorValue{uint64_t{42}});

    auto result = build("Outer()/Inner()", registry);

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());
    ASSERT_EQ(result.packet->size(), 2);
    EXPECT_EQ(std::get<uint64_t>(field((*result.packet)[0], "type").value), 42);
    EXPECT_FALSE(field((*result.packet)[0], "type").explicitly_set);
}

TEST(PacketConstructorTest, InvalidInferenceRuleTargetFailsAtRegistration) {
    Registry registry;
    registry.register_header("Outer", {{"type", "b16"}});
    registry.register_header("Inner", {{"field", "b8"}});

    EXPECT_THROW(registry.register_inference_rule("Outer",
                                                 "Inner",
                                                 "unknown",
                                                 ConstructorValue{uint64_t{42}}),
                 std::invalid_argument);
}

TEST(PacketConstructorTest, InvalidInferenceRuleValueFailsAtRegistration) {
    Registry registry;
    registry.register_header("Outer", {{"type", "b8"}});
    registry.register_header("Inner", {{"field", "b8"}});

    EXPECT_THROW(registry.register_inference_rule("Outer",
                                                 "Inner",
                                                 "type",
                                                 ConstructorValue{uint64_t{256}}),
                 std::invalid_argument);
}

TEST(PacketConstructorTest, VlanValuesOverrideDefaults) {
    auto result = build("VLAN(prio=7,dei=1,vlan=4095,type=0x0800)");

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());
    ASSERT_EQ(result.packet->size(), 1);

    const auto& vlan = (*result.packet)[0];
    EXPECT_EQ(std::get<uint64_t>(field(vlan, "prio").value), 7);
    EXPECT_EQ(std::get<uint64_t>(field(vlan, "dei").value), 1);
    EXPECT_EQ(std::get<uint64_t>(field(vlan, "vlan").value), 4095);
    EXPECT_EQ(std::get<uint64_t>(field(vlan, "type").value), 0x0800);
    EXPECT_TRUE(field(vlan, "prio").explicitly_set);
    EXPECT_TRUE(field(vlan, "dei").explicitly_set);
    EXPECT_TRUE(field(vlan, "vlan").explicitly_set);
    EXPECT_TRUE(field(vlan, "type").explicitly_set);
}

TEST(PacketConstructorTest, VxlanDefaultsAndValues) {
    auto result = build("UDP()/VXLAN(vni=100)");

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());
    ASSERT_EQ(result.packet->size(), 2);

    const auto& vxlan = (*result.packet)[1];
    EXPECT_EQ(vxlan.protocol, "VXLAN");
    EXPECT_EQ(vxlan.offset, 8);
    ASSERT_EQ(vxlan.fields.size(), 4);
    EXPECT_EQ(vxlan.fields[0].name, "flags");
    EXPECT_EQ(vxlan.fields[1].name, "reserved");
    EXPECT_EQ(vxlan.fields[2].name, "vni");
    EXPECT_EQ(vxlan.fields[3].name, "reserved2");
    EXPECT_EQ(std::get<uint64_t>(field(vxlan, "flags").value), 0x08);
    EXPECT_EQ(std::get<uint64_t>(field(vxlan, "vni").value), 100);
    EXPECT_EQ(std::get<uint64_t>(field((*result.packet)[0], "dport").value), 4789);
    EXPECT_FALSE(field((*result.packet)[0], "dport").explicitly_set);
    EXPECT_FALSE(field(vxlan, "flags").explicitly_set);
    EXPECT_TRUE(field(vxlan, "vni").explicitly_set);
}

TEST(PacketConstructorTest, PayloadLengthAdvancesFollowingHeaderOffset) {
    auto result = build("Ether()/Payload(length=32)/UDP()");

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());
    ASSERT_EQ(result.packet->size(), 3);

    const auto& payload = (*result.packet)[1];
    EXPECT_EQ(payload.protocol, "Payload");
    EXPECT_EQ(payload.offset, 14);
    EXPECT_TRUE(payload.fields.empty());
    ASSERT_EQ(payload.options.size(), 1);
    EXPECT_EQ(std::get<uint64_t>(scalar_option(payload, "length")), 32);
    EXPECT_TRUE(option(payload, "length").explicitly_set);
    EXPECT_EQ((*result.packet)[2].offset, 46);
}

TEST(PacketConstructorTest, PayloadTotalLengthCalculatesPayloadLength) {
    auto result = build("Ether()/IP()/Payload(total_length=100)");

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());

    const auto& payload = (*result.packet)[2];
    EXPECT_EQ(payload.offset, 34);
    EXPECT_EQ(std::get<uint64_t>(scalar_option(payload, "length")), 66);
    EXPECT_FALSE(option(payload, "length").explicitly_set);
    EXPECT_EQ(std::get<uint64_t>(scalar_option(payload, "total_length")), 100);
    EXPECT_TRUE(option(payload, "total_length").explicitly_set);
}

TEST(PacketConstructorTest, PayloadTotalLengthRejectsTooSmallPacket) {
    auto result = build("Ether()/IP()/Payload(total_length=20)");

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_NE(result.errors[0].find("smaller than preceding header length 34"), std::string::npos);
}

TEST(PacketConstructorTest, PayloadRejectsConflictingLengthOptions) {
    auto result = build("Ether()/Payload(length=10,total_length=64)");

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_NE(result.errors[0].find("cannot both be explicitly set"), std::string::npos);
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

TEST(PacketConstructorTest, VlanBitWidthOverflowFails) {
    auto result = build("VLAN(vlan=4096)");

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_NE(result.errors[0].find("12 bits"), std::string::npos);
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

TEST(PacketConstructorTest, OptionsAreConstructedButNotSerializedFields) {
    Registry registry;
    registry.register_header("Payload", {}, {
        {"length", "b64", ConstructorValue{uint64_t{64}}},
    });

    auto result = build("Payload(length=100)", registry);

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());
    ASSERT_EQ(result.packet->size(), 1);

    const auto& payload = (*result.packet)[0];
    EXPECT_TRUE(payload.fields.empty());
    ASSERT_EQ(payload.options.size(), 1);
    EXPECT_EQ(std::get<uint64_t>(scalar_option(payload, "length")), 100);
    EXPECT_TRUE(option(payload, "length").explicitly_set);
}

TEST(PacketConstructorTest, OptionsUseDefaults) {
    Registry registry;
    registry.register_header("Payload", {}, {
        {"length", "b64", ConstructorValue{uint64_t{64}}},
    });

    auto result = build("Payload()", registry);

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());

    const auto& payload = (*result.packet)[0];
    EXPECT_TRUE(payload.fields.empty());
    ASSERT_EQ(payload.options.size(), 1);
    EXPECT_EQ(std::get<uint64_t>(scalar_option(payload, "length")), 64);
    EXPECT_FALSE(option(payload, "length").explicitly_set);
}

TEST(PacketConstructorTest, PacketValuedOptionsConstructNestedPacket) {
    Registry registry;
    registry.register_header("Outer", {{"field", "b8"}}, {
        {"children", "", std::nullopt, AttrValueKind::Packet},
    });
    registry.register_header("InnerA", {{"a", "b8"}});
    registry.register_header("InnerB", {{"b", "b16"}});

    auto result = build("Outer(children=InnerA(a=1)/InnerB(b=2))", registry);

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());
    const auto& outer = (*result.packet)[0];
    ASSERT_EQ(outer.options.size(), 1);
    EXPECT_TRUE(option(outer, "children").explicitly_set);

    const auto& children = packet_option(outer, "children");
    ASSERT_EQ(children.size(), 2);
    EXPECT_EQ(children[0].protocol, "InnerA");
    EXPECT_EQ(std::get<uint64_t>(field(children[0], "a").value), 1);
    EXPECT_EQ(children[1].protocol, "InnerB");
    EXPECT_EQ(std::get<uint64_t>(field(children[1], "b").value), 2);
}

TEST(PacketConstructorTest, PacketValuedOptionRejectsScalarValue) {
    Registry registry;
    registry.register_header("Outer", {}, {
        {"children", "", std::nullopt, AttrValueKind::Packet},
    });

    auto result = build("Outer(children=1)", registry);

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_NE(result.errors[0].find("requires a packet value"), std::string::npos);
}

TEST(PacketConstructorTest, ScalarFieldRejectsPacketValue) {
    Registry registry;
    registry.register_header("Outer", {{"field", "b8"}});
    registry.register_header("Inner", {{"value", "b8"}});

    auto result = build("Outer(field=Inner(value=1))", registry);

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_NE(result.errors[0].find("requires a scalar value"), std::string::npos);
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

TEST(PacketConstructorTest, BitRangesParsePrefixedIntegerSyntax) {
    Registry registry;
    registry.register_header("MyHdr", {
        {"unquoted", "b16_ranges"},
        {"quoted", "b16_ranges"},
    });

    auto result = build(R"(MyHdr(unquoted=0b1010,quoted="0x10"))", registry);

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());

    const auto& header = (*result.packet)[0];
    EXPECT_EQ(std::get<uint64_t>(field(header, "unquoted").value), 10);
    EXPECT_EQ(std::get<uint64_t>(field(header, "quoted").value), 16);
}

TEST(PacketConstructorTest, BitRangesNormalizeRangeSyntax) {
    Registry registry;
    registry.register_header("MyHdr", {
        {"range", "b16_ranges"},
        {"list", "b16_ranges"},
    });

    auto result = build(R"(MyHdr(range="0x1-0b10",list="[1, 0b10-0x3]"))", registry);

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
