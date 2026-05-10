#pragma once

#include <cstddef>
#include <iosfwd>
#include <span>
#include <string>
#include <vector>

namespace packet {

struct PcapWriteResult {
    bool ok = false;
    std::vector<std::string> errors;
};

class PcapWriter {
public:
    explicit PcapWriter(std::ostream& output);

    PcapWriteResult write_header();
    PcapWriteResult write_packet(std::span<const std::byte> payload);

private:
    std::ostream& output_;
    bool wrote_header_ = false;
};

} // namespace packet
