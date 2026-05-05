#include "packet/parser.hpp"
#include "packet/runtime.hpp"

#include <gtest/gtest.h>

#include <string>

using namespace packet;

namespace {

Program parse_program(std::string_view input) {
    Parser parser(input);
    auto program = parser.parse();
    EXPECT_TRUE(program.has_value()) << parser.last_error();
    return std::move(*program);
}

} // namespace

TEST(RuntimeTest, ValidMandatoryVariables) {
    auto program = parse_program(R"(DPDK_ARGS: "--no-huge -l 0"
PACKET: Ether()/IP(src="192.168.0.1"))");

    Runtime runtime;
    auto result = runtime.check(program);

    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.errors.empty());
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
