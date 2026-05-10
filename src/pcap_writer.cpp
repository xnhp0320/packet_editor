#include "packet/pcap_writer.hpp"

#include <cstdint>
#include <limits>
#include <ostream>

namespace packet {

namespace {

constexpr uint32_t pcap_magic = 0xa1b2c3d4;
constexpr uint16_t pcap_major = 2;
constexpr uint16_t pcap_minor = 4;
constexpr uint32_t pcap_snaplen = 65535;
constexpr uint32_t pcap_linktype_ethernet = 1;

void write_u16_le(std::ostream& output, uint16_t value) {
    const char bytes[] = {
        static_cast<char>(value & 0xff),
        static_cast<char>((value >> 8) & 0xff),
    };
    output.write(bytes, sizeof(bytes));
}

void write_u32_le(std::ostream& output, uint32_t value) {
    const char bytes[] = {
        static_cast<char>(value & 0xff),
        static_cast<char>((value >> 8) & 0xff),
        static_cast<char>((value >> 16) & 0xff),
        static_cast<char>((value >> 24) & 0xff),
    };
    output.write(bytes, sizeof(bytes));
}

PcapWriteResult stream_result(const std::ostream& output) {
    if (output) {
        return PcapWriteResult{true, {}};
    }
    return PcapWriteResult{false, {"failed to write pcap output"}};
}

} // namespace

PcapWriter::PcapWriter(std::ostream& output)
    : output_(output)
{
}

PcapWriteResult PcapWriter::write_header() {
    write_u32_le(output_, pcap_magic);
    write_u16_le(output_, pcap_major);
    write_u16_le(output_, pcap_minor);
    write_u32_le(output_, 0);
    write_u32_le(output_, 0);
    write_u32_le(output_, pcap_snaplen);
    write_u32_le(output_, pcap_linktype_ethernet);

    auto result = stream_result(output_);
    wrote_header_ = result.ok;
    return result;
}

PcapWriteResult PcapWriter::write_packet(std::span<const std::byte> payload) {
    if (!wrote_header_) {
        return PcapWriteResult{false, {"pcap header must be written before packet records"}};
    }
    if (payload.size() > pcap_snaplen ||
        payload.size() > std::numeric_limits<uint32_t>::max()) {
        return PcapWriteResult{false, {"packet is too large for pcap output"}};
    }

    const auto len = static_cast<uint32_t>(payload.size());
    write_u32_le(output_, 0);
    write_u32_le(output_, 0);
    write_u32_le(output_, len);
    write_u32_le(output_, len);
    output_.write(reinterpret_cast<const char*>(payload.data()),
                  static_cast<std::streamsize>(payload.size()));
    return stream_result(output_);
}

} // namespace packet
