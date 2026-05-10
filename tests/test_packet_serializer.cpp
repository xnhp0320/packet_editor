#include "packet/packet_serializer.hpp"
#include "packet/parser.hpp"
#include "packet/registry.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

using namespace packet;

namespace {

constexpr uint8_t udp_protocol_number = 17;

Packet parse_packet(std::string_view input) {
    Parser parser(input);
    auto packet = parser.parse_packet();
    EXPECT_TRUE(packet.has_value()) << parser.last_error();
    return std::move(*packet);
}

PacketConstructor build_constructor(std::string_view input, const Registry& registry) {
    PacketConstructorBuilder builder{registry};
    auto result = builder.build(parse_packet(input));
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.packet.has_value());
    return std::move(*result.packet);
}

PacketConstructor build_constructor(std::string_view input) {
    Registry registry;
    return build_constructor(input, registry);
}

SerializeResult serialize_into(const PacketConstructor& packet, std::vector<std::byte>& storage) {
    Registry registry;
    return serialize_packet(packet, registry, PacketBufferView{storage});
}

const PayloadFieldModifier* find_modifier(const SerializeResult& result,
                                          std::string_view protocol,
                                          std::string_view field) {
    auto it = std::ranges::find_if(result.modifiers, [protocol, field](const PayloadFieldModifier& modifier) {
        return modifier.protocol == protocol && modifier.field == field;
    });
    return it == result.modifiers.end() ? nullptr : &*it;
}

uint8_t byte_at(std::span<const std::byte> bytes, size_t offset) {
    return std::to_integer<uint8_t>(bytes[offset]);
}

uint16_t u16_at(std::span<const std::byte> bytes, size_t offset) {
    return static_cast<uint16_t>((static_cast<uint16_t>(byte_at(bytes, offset)) << 8) |
                                 byte_at(bytes, offset + 1));
}

uint32_t checksum_sum(std::span<const std::byte> bytes) {
    uint32_t sum = 0;
    size_t offset = 0;
    while (offset + 1 < bytes.size()) {
        sum += u16_at(bytes, offset);
        offset += 2;
    }
    if (offset < bytes.size()) {
        sum += static_cast<uint16_t>(byte_at(bytes, offset) << 8);
    }
    return sum;
}

uint16_t fold(uint32_t sum) {
    while ((sum >> 16) != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return static_cast<uint16_t>(sum);
}

uint32_t ipv4_udp_pseudo_sum(std::span<const std::byte> bytes, size_t ip_offset, uint16_t udp_len) {
    uint32_t sum = 0;
    sum += u16_at(bytes, ip_offset + 12);
    sum += u16_at(bytes, ip_offset + 14);
    sum += u16_at(bytes, ip_offset + 16);
    sum += u16_at(bytes, ip_offset + 18);
    sum += udp_protocol_number;
    sum += udp_len;
    return sum;
}

} // namespace

TEST(PacketSerializerTest, SerializesEtherIpUdpScalars) {
    auto packet = build_constructor(
        std::format(R"(Ether(dst="ff:ff:ff:ff:ff:ff",src="00:11:22:33:44:55",type=2048)/IP(src="192.168.0.1",dst="192.168.0.2",ttl=64,proto={})/UDP(sport=53,dport=54))",
                    udp_protocol_number));
    std::vector<std::byte> payload(64);

    auto result = serialize_into(packet, payload);

    ASSERT_TRUE(result.ok);
    EXPECT_EQ(result.packet_len, 42);
    EXPECT_EQ(byte_at(payload, 0), 0xff);
    EXPECT_EQ(byte_at(payload, 5), 0xff);
    EXPECT_EQ(byte_at(payload, 6), 0x00);
    EXPECT_EQ(byte_at(payload, 7), 0x11);
    EXPECT_EQ(byte_at(payload, 11), 0x55);
    EXPECT_EQ(u16_at(payload, 12), 0x0800);
    EXPECT_EQ(byte_at(payload, 14), 0x45);
    EXPECT_EQ(byte_at(payload, 22), 64);
    EXPECT_EQ(byte_at(payload, 23), udp_protocol_number);
    EXPECT_EQ(byte_at(payload, 26), 192);
    EXPECT_EQ(byte_at(payload, 29), 1);
    EXPECT_EQ(byte_at(payload, 33), 2);
    EXPECT_EQ(u16_at(payload, 34), 53);
    EXPECT_EQ(u16_at(payload, 36), 54);
    EXPECT_EQ(u16_at(payload, 38), 0);
}

TEST(PacketSerializerTest, SerializesVlanCrossByteFields) {
    auto packet = build_constructor("VLAN(prio=7,dei=1,vlan=4095,type=2048)");
    std::vector<std::byte> payload(4);

    auto result = serialize_into(packet, payload);

    ASSERT_TRUE(result.ok);
    EXPECT_EQ(result.packet_len, 4);
    EXPECT_EQ(byte_at(payload, 0), 0xff);
    EXPECT_EQ(byte_at(payload, 1), 0xff);
    EXPECT_EQ(u16_at(payload, 2), 0x0800);
}

TEST(PacketSerializerTest, RejectsSmallOutputBuffer) {
    auto packet = build_constructor("Ether()/IP()/UDP()");
    std::vector<std::byte> payload(8);

    auto result = serialize_into(packet, payload);

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_NE(result.errors[0].find("packet requires 42 bytes"), std::string::npos);
}

TEST(PacketSerializerTest, PayloadLengthExtendsSerializedPacket) {
    auto packet = build_constructor("Ether()/Payload(length=32)");
    std::vector<std::byte> payload(64, std::byte{0xff});

    auto result = serialize_into(packet, payload);

    ASSERT_TRUE(result.ok);
    EXPECT_EQ(result.packet_len, 46);
    EXPECT_EQ(byte_at(payload, 14), 0);
    EXPECT_EQ(byte_at(payload, 45), 0);
    EXPECT_EQ(byte_at(payload, 46), 0xff);
}

TEST(PacketSerializerTest, PayloadTotalLengthExtendsSerializedPacket) {
    auto packet = build_constructor("Ether()/IP()/Payload(total_length=100)");
    std::vector<std::byte> payload(128);

    auto result = serialize_into(packet, payload);

    ASSERT_TRUE(result.ok);
    EXPECT_EQ(result.packet_len, 100);
}

TEST(PacketSerializerTest, SerializesIpv4OptionsAndAdvancesNextHeader) {
    auto packet = build_constructor("IP(options=IPOption_NOP()/IPOption_EOL())/TCP()");
    std::vector<std::byte> payload(64);

    auto result = serialize_into(packet, payload);

    ASSERT_TRUE(result.ok);
    EXPECT_EQ(result.packet_len, 44);
    EXPECT_EQ(byte_at(payload, 0), 0x46);
    EXPECT_EQ(byte_at(payload, 20), 1);
    EXPECT_EQ(byte_at(payload, 21), 0);
    EXPECT_EQ(byte_at(payload, 22), 0);
    EXPECT_EQ(byte_at(payload, 23), 0);
    EXPECT_EQ(byte_at(payload, 24 + 12), 0x50);
}

TEST(PacketSerializerTest, SerializesTcpOptionsAndPadsHeader) {
    auto packet = build_constructor("IP()/TCP(options=TCPOption_MSS(value=1460))");
    std::vector<std::byte> payload(64);

    auto result = serialize_into(packet, payload);

    ASSERT_TRUE(result.ok);
    EXPECT_EQ(result.packet_len, 44);
    EXPECT_EQ(byte_at(payload, 20 + 12), 0x60);
    EXPECT_EQ(byte_at(payload, 40), 2);
    EXPECT_EQ(byte_at(payload, 41), 4);
    EXPECT_EQ(u16_at(payload, 42), 1460);
}

TEST(PacketSerializerTest, TcpOptionHeaderLengthFeedsHardwareOffload) {
    auto packet = build_constructor("IP()/TCP(options=TCPOption_MSS(value=1460))/Payload(length=4)");
    std::vector<std::byte> payload(64);

    auto serialize = serialize_into(packet, payload);
    ASSERT_TRUE(serialize.ok);

    FixupOptions options;
    options.tcp_checksum = FixupMode::HardwareOffload;
    auto fixup = fixup_packet(packet, Registry{}, PacketBufferView{payload}, serialize.packet_len, options);

    ASSERT_TRUE(fixup.ok);
    EXPECT_TRUE(fixup.offload.tcp_checksum);
    EXPECT_EQ(fixup.offload.l3_len, 20);
    EXPECT_EQ(fixup.offload.l4_len, 24);
}

TEST(PacketSerializerTest, SerializesFirstRangeValueIntoBasePayload) {
    auto packet = build_constructor(R"(IP(src="[10.0.0.2-10.0.0.4]",dst="10.0.1.1-10.0.1.2"))");
    std::vector<std::byte> payload(20);

    auto result = serialize_into(packet, payload);

    ASSERT_TRUE(result.ok);
    EXPECT_EQ(byte_at(payload, 12), 10);
    EXPECT_EQ(byte_at(payload, 15), 2);
    EXPECT_EQ(byte_at(payload, 16), 10);
    EXPECT_EQ(byte_at(payload, 19), 1);
    auto* src_modifier = find_modifier(result, "IP", "src");
    ASSERT_NE(src_modifier, nullptr);
    EXPECT_EQ(src_modifier->value_count, 3);
    auto* dst_modifier = find_modifier(result, "IP", "dst");
    ASSERT_NE(dst_modifier, nullptr);
    EXPECT_EQ(dst_modifier->value_count, 2);
}

TEST(PacketSerializerTest, SerializesFirstIPv6RangeValueIntoBasePayload) {
    auto packet = build_constructor(R"(IPv6(src="[2001:db8::2-2001:db8::4]"))");
    std::vector<std::byte> payload(40);

    auto result = serialize_into(packet, payload);

    ASSERT_TRUE(result.ok);
    EXPECT_EQ(byte_at(payload, 8), 0x20);
    EXPECT_EQ(byte_at(payload, 9), 0x01);
    EXPECT_EQ(byte_at(payload, 22), 0x00);
    EXPECT_EQ(byte_at(payload, 23), 0x02);
    auto* modifier = find_modifier(result, "IPv6", "src");
    ASSERT_NE(modifier, nullptr);
    EXPECT_EQ(modifier->value_count, 3);
}

TEST(PacketSerializerTest, SerializesFirstBitRangeValueIntoBasePayload) {
    Registry registry;
    registry.register_header("MyHdr", {{"field", "b16_ranges"}});
    auto packet = build_constructor(R"(MyHdr(field="[100-102]"))", registry);
    std::vector<std::byte> payload(2);

    auto result = serialize_packet(packet, registry, PacketBufferView{payload});

    ASSERT_TRUE(result.ok);
    EXPECT_EQ(u16_at(payload, 0), 100);
    auto* modifier = find_modifier(result, "MyHdr", "field");
    ASSERT_NE(modifier, nullptr);
    EXPECT_EQ(modifier->value_count, 3);
}

TEST(PacketSerializerTest, ModifierAppliesListIndexToPayload) {
    auto packet = build_constructor(R"(IP(src="[10.0.0.1-10.0.0.2, 10.0.1.1-10.0.1.2]"))");
    std::vector<std::byte> payload(20);

    auto result = serialize_into(packet, payload);
    ASSERT_TRUE(result.ok);
    auto* modifier = find_modifier(result, "IP", "src");
    ASSERT_NE(modifier, nullptr);

    std::string error;
    ASSERT_TRUE(modifier->apply(payload, 2, error)) << error;
    EXPECT_EQ(byte_at(payload, 12), 10);
    EXPECT_EQ(byte_at(payload, 13), 0);
    EXPECT_EQ(byte_at(payload, 14), 1);
    EXPECT_EQ(byte_at(payload, 15), 1);
}

TEST(PacketSerializerTest, ModifierRejectsOutOfRangeIndex) {
    auto packet = build_constructor(R"(IP(src="[10.0.0.1-10.0.0.2]"))");
    std::vector<std::byte> payload(20);

    auto result = serialize_into(packet, payload);
    ASSERT_TRUE(result.ok);
    auto* modifier = find_modifier(result, "IP", "src");
    ASSERT_NE(modifier, nullptr);

    std::string error;
    EXPECT_FALSE(modifier->apply(payload, 2, error));
    EXPECT_NE(error.find("out of range"), std::string::npos);
}

TEST(PacketSerializerTest, ModifiedPayloadCanBeFixedUpAgain) {
    auto packet = build_constructor(
        std::format(R"(Ether(type=2048)/IP(src="[192.168.0.1-192.168.0.3]",dst="192.168.0.2",ttl=64,proto={})/UDP(sport=53,dport=54))",
                    udp_protocol_number));
    std::vector<std::byte> payload(64);
    Registry registry;

    auto serialize = serialize_packet(packet, registry, PacketBufferView{payload});
    ASSERT_TRUE(serialize.ok);
    auto* modifier = find_modifier(serialize, "IP", "src");
    ASSERT_NE(modifier, nullptr);

    std::string error;
    ASSERT_TRUE(modifier->apply(payload, 2, error)) << error;
    auto fixup = fixup_packet(packet, registry, PacketBufferView{payload}, serialize.packet_len);

    ASSERT_TRUE(fixup.ok);
    EXPECT_EQ(byte_at(payload, 26), 192);
    EXPECT_EQ(byte_at(payload, 29), 3);
    EXPECT_EQ(fold(checksum_sum(std::span<const std::byte>{payload}.subspan(14, 20))), 0xffff);
    EXPECT_EQ(fold(ipv4_udp_pseudo_sum(payload, 14, 8) +
                   checksum_sum(std::span<const std::byte>{payload}.subspan(34, 8))),
              0xffff);
}

TEST(PacketSerializerTest, SoftwareFixupUpdatesLengthsAndChecksums) {
    auto packet = build_constructor(
        std::format(R"(Ether(type=2048)/IP(src="192.168.0.1",dst="192.168.0.2",ttl=64,proto={})/UDP(sport=53,dport=54))",
                    udp_protocol_number));
    std::vector<std::byte> payload(64);
    Registry registry;

    auto serialize = serialize_packet(packet, registry, PacketBufferView{payload});
    ASSERT_TRUE(serialize.ok);

    auto fixup = fixup_packet(packet, registry, PacketBufferView{payload}, serialize.packet_len);

    ASSERT_TRUE(fixup.ok);
    EXPECT_EQ(u16_at(payload, 16), 28);
    EXPECT_EQ(u16_at(payload, 38), 8);
    EXPECT_EQ(fold(checksum_sum(std::span<const std::byte>{payload}.subspan(14, 20))), 0xffff);
    EXPECT_EQ(fold(ipv4_udp_pseudo_sum(payload, 14, 8) +
                   checksum_sum(std::span<const std::byte>{payload}.subspan(34, 8))),
              0xffff);
}

TEST(PacketSerializerTest, HardwareFixupRecordsOffloadRequest) {
    auto packet = build_constructor(
        std::format(R"(Ether(type=2048)/IP(src="192.168.0.1",dst="192.168.0.2",ttl=64,proto={})/UDP(sport=53,dport=54))",
                    udp_protocol_number));
    std::vector<std::byte> payload(64);
    Registry registry;
    auto serialize = serialize_packet(packet, registry, PacketBufferView{payload});
    ASSERT_TRUE(serialize.ok);

    FixupOptions options;
    options.ipv4_checksum = FixupMode::HardwareOffload;
    options.udp_checksum = FixupMode::HardwareOffload;
    auto fixup = fixup_packet(packet, registry, PacketBufferView{payload}, serialize.packet_len, options);

    ASSERT_TRUE(fixup.ok);
    EXPECT_EQ(fixup.offload.layer3, OffloadLayer3::IPv4);
    EXPECT_TRUE(fixup.offload.ipv4_checksum);
    EXPECT_TRUE(fixup.offload.udp_checksum);
    EXPECT_FALSE(fixup.offload.tcp_checksum);
    EXPECT_EQ(fixup.offload.l2_len, 14);
    EXPECT_EQ(fixup.offload.l3_len, 20);
    EXPECT_EQ(fixup.offload.l4_len, 8);
    EXPECT_EQ(u16_at(payload, 24), 0);
    EXPECT_NE(u16_at(payload, 40), 0);
}

TEST(PacketSerializerTest, DisabledChecksumModePreservesExplicitChecksumFields) {
    auto packet = build_constructor(
        std::format(R"(Ether(type=2048)/IP(src="192.168.0.1",dst="192.168.0.2",chksum=9,proto={})/UDP(sport=53,dport=54,chksum=10))",
                    udp_protocol_number));
    std::vector<std::byte> payload(64);
    Registry registry;
    auto serialize = serialize_packet(packet, registry, PacketBufferView{payload});
    ASSERT_TRUE(serialize.ok);

    FixupOptions options;
    options.ipv4_checksum = FixupMode::Disabled;
    options.udp_checksum = FixupMode::Disabled;
    auto fixup = fixup_packet(packet, registry, PacketBufferView{payload}, serialize.packet_len, options);

    ASSERT_TRUE(fixup.ok);
    EXPECT_EQ(u16_at(payload, 16), 28);
    EXPECT_EQ(u16_at(payload, 38), 8);
    EXPECT_EQ(u16_at(payload, 24), 9);
    EXPECT_EQ(u16_at(payload, 40), 10);
}
