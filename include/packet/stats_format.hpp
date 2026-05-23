#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace packet {

std::string format_human_count(double value);
std::string format_human_rate(double value, std::string_view suffix);
std::string format_elapsed_seconds(uint64_t seconds);

} // namespace packet
