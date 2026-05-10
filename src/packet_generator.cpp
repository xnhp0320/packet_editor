#include "packet/packet_generator.hpp"

#include "packet/checker.hpp"

#include <algorithm>
#include <format>
#include <limits>
#include <optional>
#include <span>
#include <utility>

namespace packet {

namespace {

constexpr size_t generator_max_packet_size = 2048;

std::optional<PacketConstructor> build_packet_constructor(const Packet& packet,
                                                          const Registry& registry,
                                                          PacketGenerationResult& result) {
    PacketConstructorBuilder builder{registry};
    auto constructor = builder.build(packet);
    result.warnings.insert(result.warnings.end(), constructor.warnings.begin(), constructor.warnings.end());
    result.errors.insert(result.errors.end(), constructor.errors.begin(), constructor.errors.end());
    if (!constructor.ok || !constructor.packet) {
        return std::nullopt;
    }
    return std::move(*constructor.packet);
}

std::optional<GeneratedPacket> serialize_generated_packet(PacketConstructor packet,
                                                          const Registry& registry,
                                                          PacketGenerationResult& result) {
    std::vector<std::byte> payload(generator_max_packet_size);
    auto serialized = serialize_packet(packet, registry, PacketBufferView{payload});
    result.errors.insert(result.errors.end(), serialized.errors.begin(), serialized.errors.end());
    if (!serialized.ok) {
        return std::nullopt;
    }

    auto fixed = fixup_packet(packet, registry, PacketBufferView{payload}, serialized.packet_len);
    result.errors.insert(result.errors.end(), fixed.errors.begin(), fixed.errors.end());
    if (!fixed.ok) {
        return std::nullopt;
    }

    payload.resize(serialized.packet_len);
    return GeneratedPacket{
        std::move(packet),
        std::move(payload),
        std::move(serialized.modifiers),
        serialized.packet_len,
        {},
    };
}

std::optional<FlowIndexPlan> plan_flow_indexes(const std::vector<PayloadFieldModifier>& modifiers,
                                               std::optional<uint64_t> packet_count,
                                               PacketGenerationResult& result) {
    FlowIndexPlan plan;
    for (const auto& modifier : modifiers) {
        if (modifier.value_count == 0) {
            result.errors.push_back(std::format("modifier '{}.{}' has zero values",
                                                modifier.protocol,
                                                modifier.field));
            return std::nullopt;
        }
        if (plan.total_flows > std::numeric_limits<uint64_t>::max() / modifier.value_count) {
            result.errors.push_back("range expansion has more than 18446744073709551615 flows");
            return std::nullopt;
        }
        plan.total_flows *= modifier.value_count;
    }

    plan.planned_packets = packet_count ? std::min(plan.total_flows, *packet_count)
                                        : plan.total_flows;
    return plan;
}

bool apply_flow_index(std::span<std::byte> payload,
                      const std::vector<PayloadFieldModifier>& modifiers,
                      uint64_t flow_index,
                      std::vector<std::string>& errors) {
    uint64_t divisor = 1;
    for (const auto& modifier : modifiers) {
        const auto value_index = (flow_index / divisor) % modifier.value_count;
        std::string error;
        if (!modifier.apply(payload, value_index, error)) {
            errors.push_back(std::move(error));
            return false;
        }
        divisor *= modifier.value_count;
    }
    return true;
}

} // namespace

PacketGenerator::PacketGenerator(const Registry& registry)
    : registry_(registry)
{
}

PacketGenerationResult PacketGenerator::prepare(const Packet& packet,
                                                std::optional<uint64_t> packet_count) const {
    PacketGenerationResult result;

    Checker checker{registry_};
    auto check = checker.check(packet);
    result.warnings.insert(result.warnings.end(), check.warnings.begin(), check.warnings.end());
    result.errors.insert(result.errors.end(), check.errors.begin(), check.errors.end());
    if (!check.ok) {
        return result;
    }

    auto constructor = build_packet_constructor(packet, registry_, result);
    if (!constructor) {
        return result;
    }

    auto generated = serialize_generated_packet(std::move(*constructor), registry_, result);
    if (!generated) {
        return result;
    }

    auto flow_plan = plan_flow_indexes(generated->modifiers, packet_count, result);
    if (!flow_plan) {
        return result;
    }
    generated->flow_plan = *flow_plan;

    result.ok = true;
    result.packet = std::move(*generated);
    return result;
}

bool PacketGenerator::payload_for_flow(const GeneratedPacket& packet,
                                       uint64_t flow_index,
                                       std::vector<std::byte>& payload,
                                       std::vector<std::string>& errors) const {
    if (flow_index >= packet.flow_plan.planned_packets) {
        errors.push_back("flow index is outside the planned packet count");
        return false;
    }

    payload = packet.base_payload;
    if (!apply_flow_index(payload, packet.modifiers, flow_index, errors)) {
        return false;
    }

    auto fixed = fixup_packet(packet.constructor, registry_, PacketBufferView{payload}, packet.packet_len);
    errors.insert(errors.end(), fixed.errors.begin(), fixed.errors.end());
    return fixed.ok;
}

} // namespace packet
