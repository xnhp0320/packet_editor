#include "packet/stats_format.hpp"

#include <array>
#include <cmath>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>

namespace packet {

namespace {

struct ScaledValue {
    double value = 0.0;
    std::string_view prefix;
};

ScaledValue scale_decimal(double value) {
    constexpr std::array<std::string_view, 4> prefixes{"", "K", "M", "G"};
    size_t index = 0;
    while (std::abs(value) >= 1000.0 && index + 1 < prefixes.size()) {
        value /= 1000.0;
        ++index;
    }
    return ScaledValue{value, prefixes[index]};
}

} // namespace

std::string format_human_count(double value) {
    const auto scaled = scale_decimal(value);
    if (scaled.prefix.empty()) {
        return std::format("{:.0f}", scaled.value);
    }
    return std::format("{:.2f} {}", scaled.value, scaled.prefix);
}

std::string format_human_rate(double value, std::string_view suffix) {
    const auto scaled = scale_decimal(value);
    if (scaled.prefix.empty()) {
        return std::format("{:.0f} {}", scaled.value, suffix);
    }
    return std::format("{:.2f} {}{}", scaled.value, scaled.prefix, suffix);
}

std::string format_elapsed_seconds(uint64_t seconds) {
    const auto hours = seconds / 3600;
    seconds %= 3600;
    const auto minutes = seconds / 60;
    seconds %= 60;
    return std::format("{:02}:{:02}:{:02}", hours, minutes, seconds);
}

} // namespace packet
