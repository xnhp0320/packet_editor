#pragma once

#include "packet/packet_constructor.hpp"
#include "packet/registry.hpp"

#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace packet {

struct PacketBufferView {
    std::span<std::byte> payload;
};

struct SerializeResult {
    bool ok = false;
    std::vector<std::string> errors;
    size_t packet_len = 0;
};

enum class FixupMode {
    Software,
    HardwareOffload,
    Disabled,
};

struct FixupOptions {
    FixupMode ipv4_checksum = FixupMode::Software;
    FixupMode tcp_checksum = FixupMode::Software;
    FixupMode udp_checksum = FixupMode::Software;
    FixupMode icmp_checksum = FixupMode::Software;
};

enum class OffloadLayer3 {
    None,
    IPv4,
    IPv6,
};

struct PacketOffloadRequest {
    OffloadLayer3 layer3 = OffloadLayer3::None;
    bool ipv4_checksum = false;
    bool tcp_checksum = false;
    bool udp_checksum = false;

    size_t l2_len = 0;
    size_t l3_len = 0;
    size_t l4_len = 0;
};

struct FixupResult {
    bool ok = false;
    std::vector<std::string> errors;
    PacketOffloadRequest offload;
};

SerializeResult serialize_packet(const PacketConstructor& packet,
                                 const Registry& registry,
                                 PacketBufferView output);

FixupResult fixup_packet(const PacketConstructor& packet,
                         const Registry& registry,
                         PacketBufferView buffer,
                         size_t packet_len,
                         const FixupOptions& options = {});

} // namespace packet
