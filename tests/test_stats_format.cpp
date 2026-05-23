#include "packet/stats_format.hpp"

#include <gtest/gtest.h>

using namespace packet;

TEST(StatsFormatTest, FormatsCounts) {
    EXPECT_EQ(format_human_count(999), "999");
    EXPECT_EQ(format_human_count(1500), "1.50 K");
    EXPECT_EQ(format_human_count(2000000), "2.00 M");
}

TEST(StatsFormatTest, FormatsRates) {
    EXPECT_EQ(format_human_rate(999, "pps"), "999 pps");
    EXPECT_EQ(format_human_rate(1500, "pps"), "1.50 Kpps");
    EXPECT_EQ(format_human_rate(2000000, "pps"), "2.00 Mpps");
    EXPECT_EQ(format_human_rate(800, "bps"), "800 bps");
    EXPECT_EQ(format_human_rate(1200000, "bps"), "1.20 Mbps");
    EXPECT_EQ(format_human_rate(3400000000.0, "bps"), "3.40 Gbps");
}

TEST(StatsFormatTest, FormatsElapsedSeconds) {
    EXPECT_EQ(format_elapsed_seconds(1), "00:00:01");
    EXPECT_EQ(format_elapsed_seconds(3723), "01:02:03");
}
