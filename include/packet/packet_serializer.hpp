#pragma once

#include "packet/packet_constructor.hpp"
#include "packet/registry.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace packet {

struct PacketBufferView {
    std::span<std::byte> payload;
};

class PayloadFieldModifier {
public:
    using RangeValues = std::variant<
        std::vector<UIntRange>,
        std::vector<IPv4Range>,
        std::vector<IPv6Range>>;

    std::string protocol;
    std::string field;
    size_t bit_offset = 0;
    size_t bit_width = 0;
    uint64_t value_count = 0;
    RangeValues values;

    bool apply(std::span<std::byte> payload, uint64_t value_index, std::string& error) const;
};

struct SerializeResult {
    bool ok = false;
    std::vector<std::string> errors;
    size_t packet_len = 0;
    std::vector<PayloadFieldModifier> modifiers;
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

struct Ipv4Fixup {
    size_t offset = 0;
    size_t header_len = 0;
    FixupMode checksum = FixupMode::Software;
};

struct Ipv6Fixup {
    size_t offset = 0;
    size_t header_len = 40;
};

struct UdpFixup {
    size_t offset = 0;
    FixupMode checksum = FixupMode::Software;
};

struct TcpFixup {
    size_t offset = 0;
    size_t header_len = 0;
    FixupMode checksum = FixupMode::Software;
};

struct IcmpFixup {
    size_t offset = 0;
    FixupMode checksum = FixupMode::Software;
};

struct PacketFixupPlan {
    size_t packet_len = 0;
    std::optional<Ipv4Fixup> ipv4;
    std::optional<Ipv6Fixup> ipv6;
    std::optional<UdpFixup> udp;
    std::optional<TcpFixup> tcp;
    std::optional<IcmpFixup> icmp;
    PacketOffloadRequest offload;
};

struct FixupPlanResult {
    bool ok = false;
    std::vector<std::string> errors;
    PacketFixupPlan plan;
};

SerializeResult serialize_packet(const PacketConstructor& packet,
                                 const Registry& registry,
                                 PacketBufferView output);

FixupPlanResult plan_packet_fixups(const PacketConstructor& packet,
                                   const Registry& registry,
                                   PacketBufferView buffer,
                                   size_t packet_len,
                                   const FixupOptions& options = {});

FixupResult fixup_packet(PacketBufferView buffer,
                         const PacketFixupPlan& plan);

FixupResult fixup_packet(const PacketConstructor& packet,
                         const Registry& registry,
                         PacketBufferView buffer,
                         size_t packet_len,
                         const FixupOptions& options = {});

} // namespace packet
