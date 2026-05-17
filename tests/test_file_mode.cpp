#include "packet/packet_generator.hpp"
#include "packet/parser.hpp"
#include "packet/pcap_writer.hpp"
#include "packet/registry.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace packet;

namespace {

Packet parse_packet(std::string_view input) {
    Parser parser(input);
    auto packet = parser.parse_packet();
    EXPECT_TRUE(packet.has_value()) << parser.last_error();
    return std::move(*packet);
}

uint8_t byte_at(std::string_view bytes, size_t offset) {
    return static_cast<uint8_t>(bytes[offset]);
}

uint32_t u32_le_at(std::string_view bytes, size_t offset) {
    return static_cast<uint32_t>(byte_at(bytes, offset)) |
           (static_cast<uint32_t>(byte_at(bytes, offset + 1)) << 8) |
           (static_cast<uint32_t>(byte_at(bytes, offset + 2)) << 16) |
           (static_cast<uint32_t>(byte_at(bytes, offset + 3)) << 24);
}

} // namespace

TEST(FileModeTest, PacketGeneratorCapsRangeExpansion) {
    Registry registry;
    PacketGenerator generator{registry};
    auto result = generator.prepare(parse_packet(R"(IP(src="[10.0.0.1-10.0.0.3]"))"), 2);

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());
    EXPECT_EQ(result.packet->flow_plan.total_flows, 3);
    EXPECT_EQ(result.packet->flow_plan.planned_packets, 2);
    EXPECT_EQ(result.packet->packet_len, 20);
}

TEST(FileModeTest, PacketGeneratorProducesPerFlowPayloads) {
    Registry registry;
    PacketGenerator generator{registry};
    auto result = generator.prepare(parse_packet(R"(IP(src="[10.0.0.1-10.0.0.3]"))"));
    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());

    std::vector<std::byte> payload;
    ASSERT_TRUE(generator.payload_for_flow(*result.packet, 2, payload, result.errors));

    ASSERT_EQ(payload.size(), 20);
    EXPECT_EQ(std::to_integer<uint8_t>(payload[12]), 10);
    EXPECT_EQ(std::to_integer<uint8_t>(payload[15]), 3);
}

TEST(FileModeTest, PacketGeneratorAppliesFlowIntoPrefilledBufferRepeatedly) {
    Registry registry;
    PacketGenerator generator{registry};
    auto result = generator.prepare(parse_packet(R"(IP(src="[10.0.0.1-10.0.0.2]",dst="10.0.1.1")/UDP(sport="[10000-10001]",dport=53))"));
    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.packet.has_value());
    EXPECT_EQ(result.packet->flow_plan.total_flows, 4);

    auto reusable_payload = result.packet->base_payload;
    std::vector<std::byte> first_expected;
    std::vector<std::byte> last_expected;

    ASSERT_TRUE(generator.payload_for_flow(*result.packet, 0, first_expected, result.errors));
    ASSERT_TRUE(result.errors.empty());
    ASSERT_TRUE(generator.payload_for_flow(*result.packet, 3, last_expected, result.errors));
    ASSERT_TRUE(result.errors.empty());

    ASSERT_TRUE(generator.apply_flow(*result.packet, 0, reusable_payload, result.errors));
    ASSERT_TRUE(result.errors.empty());
    EXPECT_EQ(reusable_payload, first_expected);

    ASSERT_TRUE(generator.apply_flow(*result.packet, 3, reusable_payload, result.errors));
    ASSERT_TRUE(result.errors.empty());
    EXPECT_EQ(reusable_payload, last_expected);

    ASSERT_TRUE(generator.apply_flow(*result.packet, 0, reusable_payload, result.errors));
    ASSERT_TRUE(result.errors.empty());
    EXPECT_EQ(reusable_payload, first_expected);
}

TEST(FileModeTest, PcapWriterWritesClassicEthernetPcap) {
    std::ostringstream output;
    PcapWriter writer{output};

    std::vector<std::byte> payload{
        std::byte{0xff}, std::byte{0xff}, std::byte{0xff}, std::byte{0xff},
        std::byte{0xff}, std::byte{0xff}, std::byte{0x00}, std::byte{0x11},
        std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
        std::byte{0x08}, std::byte{0x00},
    };

    EXPECT_TRUE(writer.write_header().ok);
    EXPECT_TRUE(writer.write_packet(payload).ok);

    const auto bytes = output.str();
    ASSERT_EQ(bytes.size(), 24 + 16 + payload.size());
    EXPECT_EQ(u32_le_at(bytes, 0), 0xa1b2c3d4);
    EXPECT_EQ(u32_le_at(bytes, 16), 65535);
    EXPECT_EQ(u32_le_at(bytes, 20), 1);
    EXPECT_EQ(u32_le_at(bytes, 32), payload.size());
    EXPECT_EQ(u32_le_at(bytes, 36), payload.size());
    EXPECT_EQ(byte_at(bytes, 40), 0xff);
    EXPECT_EQ(byte_at(bytes, 45), 0xff);
    EXPECT_EQ(byte_at(bytes, 52), 0x08);
    EXPECT_EQ(byte_at(bytes, 53), 0x00);
}

TEST(FileModeTest, PcapWriterRequiresHeader) {
    std::ostringstream output;
    PcapWriter writer{output};
    std::vector<std::byte> payload{std::byte{0}};

    auto result = writer.write_packet(payload);

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "pcap header must be written before packet records");
}
