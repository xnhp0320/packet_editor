#include "packet/dpdk_offload.hpp"
#include "packet/packet_constructor.hpp"
#include "packet/packet_serializer.hpp"
#include "packet/parser.hpp"
#include "packet/registry.hpp"
#include "packet/runtime.hpp"

#include <gtest/gtest.h>

#include <rte_mbuf.h>

#include <cstddef>
#include <string>
#include <utility>
#include <variant>
#include <vector>

using namespace packet;

namespace {

Program parse_program(std::string_view input) {
    Parser parser(input);
    auto program = parser.parse();
    EXPECT_TRUE(program.has_value()) << parser.last_error();
    return std::move(*program);
}

constexpr std::string_view tap_runtime_program = R"(DPDK_ARGS: "--no-huge --no-pci -l 0"
PACKET_COUNT: 3
PACKET: Ether(dst="ff:ff:ff:ff:ff:ff",src="02:64:74:61:70:00",type=2048)/IP(src="192.168.0.1-192.168.0.3",dst="192.168.0.2",ttl=64,proto=17)/UDP(sport=1234,dport=5678))";

} // namespace

TEST(RuntimeTest, ValidMandatoryVariables) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge -l 0"
PACKET: Ether()/IP(src="192.168.0.1"))");

    Runtime runtime;
    auto result = runtime.check(program);

    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
    EXPECT_EQ(result.total_flows, 1);
    EXPECT_EQ(result.planned_packets, 1);
}

TEST(RuntimeTest, ValidTapRuntimeProgram) {
    auto program = parse_program(tap_runtime_program);

    Runtime runtime;
    auto result = runtime.check(program);

    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
    EXPECT_EQ(result.total_flows, 3);
    EXPECT_EQ(result.planned_packets, 3);
}

TEST(RuntimeTest, TapRuntimePacketSerializesAndFixesUp) {
    auto program = parse_program(tap_runtime_program);
    Registry registry;
    PacketConstructorBuilder builder{registry};
    auto constructor = builder.build(std::get<Packet>(evaluate(program.variables[2].expression)));
    ASSERT_TRUE(constructor.ok);
    ASSERT_TRUE(constructor.packet.has_value());

    std::vector<std::byte> payload(2048);
    auto serialized = serialize_packet(*constructor.packet, registry, PacketBufferView{payload});
    ASSERT_TRUE(serialized.ok);
    EXPECT_EQ(serialized.packet_len, 42);

    auto fixed = fixup_packet(*constructor.packet, registry, PacketBufferView{payload}, serialized.packet_len);
    EXPECT_TRUE(fixed.ok);
    EXPECT_TRUE(fixed.errors.empty());
}

TEST(RuntimeTest, PacketCountCapsCartesianRangeExpansion) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge --no-pci -l 0"
PACKET_COUNT: 4
PACKET: IP(src="[10.0.0.1-10.0.0.3]",dst="[10.0.1.1-10.0.1.2]"))");

    Runtime runtime;
    auto result = runtime.check(program);

    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
    EXPECT_EQ(result.total_flows, 6);
    EXPECT_EQ(result.planned_packets, 4);
}

TEST(RuntimeTest, PortRangesContributeToFlowExpansion) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge --no-pci -l 0"
PACKET: IP()/TCP(sport="[10000-10002]",dport="[20000-20001]"))");

    Runtime runtime;
    auto result = runtime.check(program);

    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
    EXPECT_EQ(result.total_flows, 6);
    EXPECT_EQ(result.planned_packets, 6);
}

TEST(RuntimeTest, PmdThreadsAndBatchSizeAreRuntimeVariables) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge --no-pci -l 0-2"
PMD_THREADS: 2
TX_BATCH_SIZE: 16
PACKET: IP(src="[10.0.0.1-10.0.0.2]",dst="[10.0.1.1-10.0.1.2]"))");

    Runtime runtime;
    auto result = runtime.check(program);

    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
    EXPECT_EQ(result.total_flows, 4);
    EXPECT_EQ(result.planned_packets, 4);
    EXPECT_EQ(result.pmd_threads, 2);
    EXPECT_EQ(result.tx_batch_size, 16);
    EXPECT_EQ(result.clone_count, 1);
    EXPECT_FALSE(result.split);
    EXPECT_EQ(result.planned_transmissions, 8);
    EXPECT_TRUE(result.workers.empty());
}

TEST(RuntimeTest, CloneCountMultipliesPlannedTransmissions) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge --no-pci -l 0"
PACKET_COUNT: 3
PACKET: IP(src="[10.0.0.1-10.0.0.4]"))");

    Runtime runtime;
    Runtime::RunOptions options;
    options.clone_count = 5;
    auto result = runtime.check(program, options);

    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
    EXPECT_EQ(result.total_flows, 4);
    EXPECT_EQ(result.planned_packets, 3);
    EXPECT_EQ(result.clone_count, 5);
    EXPECT_EQ(result.planned_transmissions, 15);
}

TEST(RuntimeTest, PmdThreadsDuplicatePlannedTransmissionsWithoutSplit) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge --no-pci -l 0-2"
PMD_THREADS: 2
PACKET: IP(src="[10.0.0.1-10.0.0.3]"))");

    Runtime runtime;
    Runtime::RunOptions options;
    options.clone_count = 2;
    auto result = runtime.check(program, options);

    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
    EXPECT_EQ(result.planned_packets, 3);
    EXPECT_EQ(result.pmd_threads, 2);
    EXPECT_FALSE(result.split);
    EXPECT_EQ(result.planned_transmissions, 12);
}

TEST(RuntimeTest, SplitPmdThreadsPartitionPlannedTransmissions) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge --no-pci -l 0-2"
PMD_THREADS: 2
PACKET: IP(src="[10.0.0.1-10.0.0.3]"))");

    Runtime runtime;
    Runtime::RunOptions options;
    options.clone_count = 2;
    options.split = true;
    auto result = runtime.check(program, options);

    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
    EXPECT_EQ(result.planned_packets, 3);
    EXPECT_EQ(result.pmd_threads, 2);
    EXPECT_TRUE(result.split);
    EXPECT_EQ(result.planned_transmissions, 6);
}

TEST(RuntimeTest, OnceOptionIsReported) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge --no-pci -l 0"
PACKET: Ether())");

    Runtime runtime;
    Runtime::RunOptions options;
    options.once = true;
    auto result = runtime.check(program, options);

    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
    EXPECT_TRUE(result.once);
    EXPECT_EQ(result.planned_transmissions, 1);
}

TEST(RuntimeTest, CloneCountMustBePositive) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge --no-pci -l 0"
PACKET: Ether())");

    Runtime runtime;
    Runtime::RunOptions options;
    options.clone_count = 0;
    auto result = runtime.check(program, options);

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "clone count must be positive");
}

TEST(RuntimeTest, PacketCountLargerThanRangeSendsOnePassOnly) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge --no-pci -l 0"
PACKET_COUNT: 10
PACKET: IP(src="10.0.0.1-10.0.0.3"))");

    Runtime runtime;
    auto result = runtime.check(program);

    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
    EXPECT_EQ(result.total_flows, 3);
    EXPECT_EQ(result.planned_packets, 3);
}

TEST(RuntimeTest, PmdThreadsMustBePositive) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge --no-pci -l 0"
PMD_THREADS: 0
PACKET: Ether())");

    Runtime runtime;
    auto result = runtime.check(program);

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "variable 'PMD_THREADS' must be positive");
}

TEST(RuntimeTest, TxBatchSizeMustBePositive) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge --no-pci -l 0"
TX_BATCH_SIZE: 0
PACKET: Ether())");

    Runtime runtime;
    auto result = runtime.check(program);

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "variable 'TX_BATCH_SIZE' must be positive");
}

TEST(RuntimeTest, TxBatchSizeIsCapped) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge --no-pci -l 0"
TX_BATCH_SIZE: 257
PACKET: Ether())");

    Runtime runtime;
    auto result = runtime.check(program);

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "variable 'TX_BATCH_SIZE' must be <= 256");
}

TEST(RuntimeTest, PacketCountMustBeInteger) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge --no-pci -l 0"
PACKET_COUNT: "3"
PACKET: Ether())");

    Runtime runtime;
    auto result = runtime.check(program);

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "variable 'PACKET_COUNT' must be an integer expression");
}

TEST(RuntimeTest, PacketCountMustBePositive) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge --no-pci -l 0"
PACKET_COUNT: 0
PACKET: Ether())");

    Runtime runtime;
    auto result = runtime.check(program);

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "variable 'PACKET_COUNT' must be positive");
}

TEST(RuntimeTest, RejectsRangeExpansionOverflow) {
    Registry registry;
    registry.register_header("Wide", {{"a", "b64_ranges"}, {"b", "b64_ranges"}});
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge --no-pci -l 0"
PACKET: Wide(a="0-18446744073709551615",b="0-18446744073709551615"))");

    Runtime runtime{std::move(registry)};
    auto result = runtime.check(program);

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "range expansion has more than 18446744073709551615 flows");
}

TEST(RuntimeTest, MissingPacket) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge -l 0")");

    Runtime runtime;
    auto result = runtime.check(program);

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "missing mandatory variable 'PACKET'");
}

TEST(RuntimeTest, DpdkArgsMustBeString) {
    auto program = parse_program(R"(DPDK_ARGS: 1
PACKET: Ether())");

    Runtime runtime;
    auto result = runtime.check(program);

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "variable 'DPDK_ARGS' must be a string expression");
}

TEST(RuntimeTest, PacketMustBePacket) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge -l 0"
PACKET: 1)");

    Runtime runtime;
    auto result = runtime.check(program);

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "variable 'PACKET' must be a packet expression");
}

TEST(RuntimeTest, PacketCheckerErrorsBlockRuntime) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge -l 0"
PACKET: BadHeader())");

    Runtime runtime;
    auto result = runtime.check(program);

    EXPECT_FALSE(result.ok);
    ASSERT_EQ(result.errors.size(), 1);
    EXPECT_EQ(result.errors[0], "unknown header: 'BadHeader'");
}

TEST(RuntimeTest, AppliesDpdkOffloadRequestToMbufMetadata) {
    rte_mbuf mbuf{};
    PacketOffloadRequest request;
    request.layer3 = OffloadLayer3::IPv4;
    request.ipv4_checksum = true;
    request.udp_checksum = true;
    request.l2_len = 14;
    request.l3_len = 20;
    request.l4_len = 8;

    apply_dpdk_offload_request(mbuf, request);

    EXPECT_TRUE((mbuf.ol_flags & RTE_MBUF_F_TX_IPV4) != 0);
    EXPECT_TRUE((mbuf.ol_flags & RTE_MBUF_F_TX_IP_CKSUM) != 0);
    EXPECT_EQ(mbuf.ol_flags & RTE_MBUF_F_TX_L4_MASK, RTE_MBUF_F_TX_UDP_CKSUM);
    EXPECT_EQ(mbuf.l2_len, 14);
    EXPECT_EQ(mbuf.l3_len, 20);
    EXPECT_EQ(mbuf.l4_len, 8);
}
