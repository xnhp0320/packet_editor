#pragma once

#include "packet/ast.hpp"
#include "packet/packet_constructor.hpp"
#include "packet/packet_serializer.hpp"
#include "packet/registry.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace packet {

struct FlowIndexPlan {
    uint64_t total_flows = 1;
    uint64_t planned_packets = 1;
};

struct GeneratedPacket {
    PacketConstructor constructor;
    std::vector<std::byte> base_payload;
    std::vector<PayloadFieldModifier> modifiers;
    size_t packet_len = 0;
    FlowIndexPlan flow_plan;
};

struct PacketGenerationResult {
    bool ok = false;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    std::optional<GeneratedPacket> packet;
};

class PacketGenerator {
public:
    explicit PacketGenerator(const Registry& registry);

    PacketGenerationResult prepare(const Packet& packet,
                                   std::optional<uint64_t> packet_count = std::nullopt) const;

    bool payload_for_flow(const GeneratedPacket& packet,
                          uint64_t flow_index,
                          std::vector<std::byte>& payload,
                          std::vector<std::string>& errors) const;

    bool apply_flow(const GeneratedPacket& packet,
                    uint64_t flow_index,
                    std::span<std::byte> payload,
                    std::vector<std::string>& errors) const;

private:
    const Registry& registry_;
};

} // namespace packet
