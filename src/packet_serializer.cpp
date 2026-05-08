#include "packet/packet_serializer.hpp"

#include <algorithm>
#include <cstdint>
#include <format>
#include <optional>
#include <string_view>
#include <utility>

namespace packet {

namespace {

constexpr uint8_t tcp_protocol = 6;
constexpr uint8_t udp_protocol = 17;

struct HeaderRef {
    const HeaderConstructor* header = nullptr;
    const HeaderSpec* spec = nullptr;
};

std::optional<HeaderRef> find_header(const PacketConstructor& packet,
                                     const Registry& registry,
                                     std::string_view protocol) {
    auto it = std::ranges::find_if(packet, [protocol](const HeaderConstructor& header) {
        return header.protocol == protocol;
    });
    if (it == packet.end()) {
        return std::nullopt;
    }

    const auto* spec = registry.find_header(it->protocol);
    if (!spec) {
        return std::nullopt;
    }
    return HeaderRef{&*it, spec};
}

const FieldSpec* find_field_spec(const HeaderSpec& header, std::string_view name) {
    auto it = std::ranges::find_if(header.fields, [name](const FieldSpec& field) {
        return field.name == name;
    });
    return it == header.fields.end() ? nullptr : &*it;
}

bool is_scalar(const IPv4Range& range) {
    return range.first == range.last;
}

bool is_scalar(const IPv6Range& range) {
    return range.first == range.last;
}

bool is_scalar(const UIntRange& range) {
    return range.first == range.last;
}

void write_bit(std::span<std::byte> payload, size_t bit_offset, bool bit) {
    auto& byte = payload[bit_offset / 8];
    const auto mask = static_cast<uint8_t>(1u << (7 - bit_offset % 8));
    auto value = std::to_integer<uint8_t>(byte);
    value = bit ? static_cast<uint8_t>(value | mask) : static_cast<uint8_t>(value & ~mask);
    byte = static_cast<std::byte>(value);
}

void write_bits(std::span<std::byte> payload, size_t bit_offset, size_t bit_width, uint64_t value) {
    for (size_t bit = 0; bit < bit_width; ++bit) {
        const auto shift = bit_width - bit - 1;
        write_bit(payload, bit_offset + bit, ((value >> shift) & 1u) != 0);
    }
}

void write_bytes(std::span<std::byte> payload, size_t bit_offset, std::span<const uint8_t> bytes) {
    for (size_t index = 0; index < bytes.size(); ++index) {
        write_bits(payload, bit_offset + index * 8, 8, bytes[index]);
    }
}

void write_u16(std::span<std::byte> payload, size_t offset, uint16_t value) {
    payload[offset] = static_cast<std::byte>(value >> 8);
    payload[offset + 1] = static_cast<std::byte>(value & 0xff);
}

uint8_t read_u8(std::span<const std::byte> payload, size_t offset) {
    return std::to_integer<uint8_t>(payload[offset]);
}

uint16_t read_u16(std::span<const std::byte> payload, size_t offset) {
    return static_cast<uint16_t>((static_cast<uint16_t>(read_u8(payload, offset)) << 8) |
                                 read_u8(payload, offset + 1));
}

uint32_t checksum_sum(std::span<const std::byte> bytes) {
    uint32_t sum = 0;
    size_t offset = 0;
    while (offset + 1 < bytes.size()) {
        sum += read_u16(bytes, offset);
        offset += 2;
    }
    if (offset < bytes.size()) {
        sum += static_cast<uint16_t>(read_u8(bytes, offset) << 8);
    }
    return sum;
}

uint32_t add_u16(uint32_t sum, uint16_t value) {
    return sum + value;
}

uint16_t fold_checksum(uint32_t sum) {
    while ((sum >> 16) != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return static_cast<uint16_t>(sum);
}

uint16_t internet_checksum(uint32_t sum) {
    return static_cast<uint16_t>(~fold_checksum(sum));
}

uint32_t ipv4_pseudo_sum(std::span<const std::byte> payload,
                         size_t ip_offset,
                         uint8_t protocol,
                         uint16_t l4_len) {
    uint32_t sum = 0;
    sum += read_u16(payload, ip_offset + 12);
    sum += read_u16(payload, ip_offset + 14);
    sum += read_u16(payload, ip_offset + 16);
    sum += read_u16(payload, ip_offset + 18);
    sum = add_u16(sum, protocol);
    sum = add_u16(sum, l4_len);
    return sum;
}

uint32_t ipv6_pseudo_sum(std::span<const std::byte> payload,
                         size_t ip_offset,
                         uint8_t protocol,
                         uint32_t l4_len) {
    uint32_t sum = checksum_sum(payload.subspan(ip_offset + 8, 32));
    sum = add_u16(sum, static_cast<uint16_t>(l4_len >> 16));
    sum = add_u16(sum, static_cast<uint16_t>(l4_len & 0xffff));
    sum = add_u16(sum, protocol);
    return sum;
}

std::optional<uint64_t> scalar_integer_value(const ConstructorValue& value,
                                             std::string_view field_name,
                                             std::string& error) {
    if (std::holds_alternative<uint64_t>(value)) {
        return std::get<uint64_t>(value);
    }
    if (std::holds_alternative<std::vector<UIntRange>>(value)) {
        const auto& ranges = std::get<std::vector<UIntRange>>(value);
        if (ranges.size() == 1 && is_scalar(ranges.front())) {
            return ranges.front().first;
        }
    }

    error = std::format("field '{}' has a non-scalar integer range value", field_name);
    return std::nullopt;
}

std::optional<IPv4> scalar_ipv4_value(const ConstructorValue& value,
                                      std::string_view field_name,
                                      std::string& error) {
    if (std::holds_alternative<IPv4>(value)) {
        return std::get<IPv4>(value);
    }
    if (std::holds_alternative<IPv4Range>(value)) {
        const auto& range = std::get<IPv4Range>(value);
        if (is_scalar(range)) {
            return range.first;
        }
    }
    if (std::holds_alternative<std::vector<IPv4Range>>(value)) {
        const auto& ranges = std::get<std::vector<IPv4Range>>(value);
        if (ranges.size() == 1 && is_scalar(ranges.front())) {
            return ranges.front().first;
        }
    }

    error = std::format("field '{}' has a non-scalar ipv4 range value", field_name);
    return std::nullopt;
}

std::optional<IPv6> scalar_ipv6_value(const ConstructorValue& value,
                                      std::string_view field_name,
                                      std::string& error) {
    if (std::holds_alternative<IPv6>(value)) {
        return std::get<IPv6>(value);
    }
    if (std::holds_alternative<IPv6Range>(value)) {
        const auto& range = std::get<IPv6Range>(value);
        if (is_scalar(range)) {
            return range.first;
        }
    }
    if (std::holds_alternative<std::vector<IPv6Range>>(value)) {
        const auto& ranges = std::get<std::vector<IPv6Range>>(value);
        if (ranges.size() == 1 && is_scalar(ranges.front())) {
            return ranges.front().first;
        }
    }

    error = std::format("field '{}' has a non-scalar ipv6 range value", field_name);
    return std::nullopt;
}

bool serialize_field(const FieldSpec& spec,
                     const FieldConstructor& field,
                     size_t bit_offset,
                     std::span<std::byte> payload,
                     std::vector<std::string>& errors) {
    std::string error;
    const auto type = spec.type_name ? std::string_view{*spec.type_name} : std::string_view{};
    if (type == "mac") {
        if (!std::holds_alternative<MacAddr>(field.value)) {
            errors.push_back(std::format("field '{}' is not a mac value", field.name));
            return false;
        }
        write_bytes(payload, bit_offset, std::get<MacAddr>(field.value).bytes());
        return true;
    }
    if (type == "ipv4" || type == "ipv4_range" || type == "ipv4_ranges") {
        auto ip = scalar_ipv4_value(field.value, field.name, error);
        if (!ip) {
            errors.push_back(std::move(error));
            return false;
        }
        write_bytes(payload, bit_offset, ip->bytes());
        return true;
    }
    if (type == "ipv6" || type == "ipv6_range" || type == "ipv6_ranges") {
        auto ip = scalar_ipv6_value(field.value, field.name, error);
        if (!ip) {
            errors.push_back(std::move(error));
            return false;
        }
        write_bytes(payload, bit_offset, ip->bytes());
        return true;
    }

    auto integer = scalar_integer_value(field.value, field.name, error);
    if (!integer) {
        errors.push_back(std::move(error));
        return false;
    }
    write_bits(payload, bit_offset, spec.bit_width, *integer);
    return true;
}

size_t packet_bit_width(const PacketConstructor& packet, const Registry& registry) {
    size_t bit_width = 0;
    for (const auto& header : packet) {
        if (const auto* spec = registry.find_header(header.protocol)) {
            bit_width = std::max(bit_width, header.offset * 8 + spec->bit_width);
        }
    }
    return bit_width;
}

void set_l4_checksum_for_offload(std::span<std::byte> payload,
                                 size_t l4_offset,
                                 uint32_t pseudo_sum) {
    write_u16(payload, l4_offset + 16, fold_checksum(pseudo_sum));
}

void set_udp_checksum_for_offload(std::span<std::byte> payload,
                                  size_t udp_offset,
                                  uint32_t pseudo_sum) {
    write_u16(payload, udp_offset + 6, fold_checksum(pseudo_sum));
}

void set_l4_lengths(PacketOffloadRequest& request,
                    const HeaderConstructor& ip_header,
                    size_t l3_len,
                    size_t l4_len) {
    request.l2_len = ip_header.offset;
    request.l3_len = l3_len;
    request.l4_len = l4_len;
}

} // namespace

SerializeResult serialize_packet(const PacketConstructor& packet,
                                 const Registry& registry,
                                 PacketBufferView output) {
    SerializeResult result;
    const auto bit_width = packet_bit_width(packet, registry);
    if (bit_width % 8 != 0) {
        result.errors.push_back(std::format("packet bit width {} is not byte-aligned", bit_width));
        return result;
    }

    result.packet_len = bit_width / 8;
    if (output.payload.size() < result.packet_len) {
        result.errors.push_back(std::format("output buffer has {} bytes but packet requires {} bytes",
                                            output.payload.size(), result.packet_len));
        return result;
    }

    std::ranges::fill(output.payload.subspan(0, result.packet_len), std::byte{0});
    for (const auto& header : packet) {
        const auto* header_spec = registry.find_header(header.protocol);
        if (!header_spec) {
            result.errors.push_back(std::format("unknown header: '{}'", header.protocol));
            continue;
        }

        for (const auto& field : header.fields) {
            const auto* spec = find_field_spec(*header_spec, field.name);
            if (!spec) {
                result.errors.push_back(std::format("unknown field '{}' in header '{}'",
                                                    field.name, header.protocol));
                continue;
            }

            const auto bit_offset = header.offset * 8 + spec->bit_offset;
            serialize_field(*spec, field, bit_offset, output.payload, result.errors);
        }
    }

    result.ok = result.errors.empty();
    return result;
}

FixupResult fixup_packet(const PacketConstructor& packet,
                         const Registry& registry,
                         PacketBufferView buffer,
                         size_t packet_len,
                         const FixupOptions& options) {
    FixupResult result;
    if (buffer.payload.size() < packet_len) {
        result.errors.push_back(std::format("buffer has {} bytes but packet length is {} bytes",
                                            buffer.payload.size(), packet_len));
        return result;
    }

    auto payload = buffer.payload.subspan(0, packet_len);

    if (auto ip = find_header(packet, registry, "IP")) {
        if (packet_len < ip->header->offset + 20) {
            result.errors.push_back("IPv4 header extends beyond packet length");
        } else {
            const auto ihl_bytes = static_cast<size_t>(read_u8(payload, ip->header->offset) & 0x0f) * 4;
            if (ihl_bytes < 20 || ip->header->offset + ihl_bytes > packet_len) {
                result.errors.push_back(std::format("invalid IPv4 IHL {} bytes", ihl_bytes));
            } else {
                const auto ip_len = packet_len - ip->header->offset;
                if (ip_len > 0xffff) {
                    result.errors.push_back(std::format("IPv4 packet length {} exceeds 16 bits", ip_len));
                } else {
                    write_u16(payload, ip->header->offset + 2, static_cast<uint16_t>(ip_len));
                }

                if (options.ipv4_checksum != FixupMode::Disabled) {
                    write_u16(payload, ip->header->offset + 10, 0);
                    if (options.ipv4_checksum == FixupMode::Software) {
                        write_u16(payload,
                                  ip->header->offset + 10,
                                  internet_checksum(checksum_sum(payload.subspan(ip->header->offset,
                                                                                 ihl_bytes))));
                    } else {
                        result.offload.ipv4_checksum = true;
                        result.offload.layer3 = OffloadLayer3::IPv4;
                        result.offload.l2_len = ip->header->offset;
                        result.offload.l3_len = ihl_bytes;
                    }
                }
            }
        }
    }

    if (auto ipv6 = find_header(packet, registry, "IPv6")) {
        constexpr size_t ipv6_header_len = 40;
        if (packet_len < ipv6->header->offset + ipv6_header_len) {
            result.errors.push_back("IPv6 header extends beyond packet length");
        } else {
            const auto payload_len = packet_len - ipv6->header->offset - ipv6_header_len;
            if (payload_len > 0xffff) {
                result.errors.push_back(std::format("IPv6 payload length {} exceeds 16 bits", payload_len));
            } else {
                write_u16(payload, ipv6->header->offset + 4, static_cast<uint16_t>(payload_len));
            }
        }
    }

    if (auto udp = find_header(packet, registry, "UDP")) {
        if (packet_len < udp->header->offset + 8) {
            result.errors.push_back("UDP header extends beyond packet length");
        } else {
            const auto udp_len = packet_len - udp->header->offset;
            if (udp_len > 0xffff) {
                result.errors.push_back(std::format("UDP length {} exceeds 16 bits", udp_len));
            } else {
                write_u16(payload, udp->header->offset + 4, static_cast<uint16_t>(udp_len));
            }

            if (options.udp_checksum != FixupMode::Disabled) {
                write_u16(payload, udp->header->offset + 6, 0);

                uint32_t pseudo_sum = 0;
                bool has_pseudo_header = false;
                if (auto ip = find_header(packet, registry, "IP")) {
                    const auto ihl_bytes = static_cast<size_t>(read_u8(payload, ip->header->offset) & 0x0f) * 4;
                    pseudo_sum = ipv4_pseudo_sum(payload,
                                                 ip->header->offset,
                                                 udp_protocol,
                                                 static_cast<uint16_t>(udp_len));
                    set_l4_lengths(result.offload, *ip->header, ihl_bytes, 8);
                    result.offload.layer3 = OffloadLayer3::IPv4;
                    has_pseudo_header = true;
                } else if (auto ipv6 = find_header(packet, registry, "IPv6")) {
                    pseudo_sum = ipv6_pseudo_sum(payload,
                                                 ipv6->header->offset,
                                                 udp_protocol,
                                                 static_cast<uint32_t>(udp_len));
                    set_l4_lengths(result.offload, *ipv6->header, 40, 8);
                    result.offload.layer3 = OffloadLayer3::IPv6;
                    has_pseudo_header = true;
                } else {
                    result.errors.push_back("UDP checksum requires IPv4 or IPv6 header");
                }

                if (has_pseudo_header && options.udp_checksum == FixupMode::Software) {
                    auto checksum = internet_checksum(pseudo_sum + checksum_sum(payload.subspan(udp->header->offset,
                                                                                                udp_len)));
                    if (checksum == 0) {
                        checksum = 0xffff;
                    }
                    write_u16(payload, udp->header->offset + 6, checksum);
                } else if (has_pseudo_header && options.udp_checksum == FixupMode::HardwareOffload) {
                    set_udp_checksum_for_offload(payload, udp->header->offset, pseudo_sum);
                    result.offload.udp_checksum = true;
                }
            }
        }
    }

    if (auto tcp = find_header(packet, registry, "TCP")) {
        if (packet_len < tcp->header->offset + 20) {
            result.errors.push_back("TCP header extends beyond packet length");
        } else if (options.tcp_checksum != FixupMode::Disabled) {
            write_u16(payload, tcp->header->offset + 16, 0);
            const auto tcp_len = packet_len - tcp->header->offset;
            const auto tcp_header_len = static_cast<size_t>(read_u8(payload, tcp->header->offset + 12) >> 4) * 4;
            if (tcp_header_len < 20 || tcp_header_len > tcp_len) {
                result.errors.push_back(std::format("invalid TCP header length {} bytes", tcp_header_len));
            }

            uint32_t pseudo_sum = 0;
            bool has_pseudo_header = false;
            if (auto ip = find_header(packet, registry, "IP")) {
                const auto ihl_bytes = static_cast<size_t>(read_u8(payload, ip->header->offset) & 0x0f) * 4;
                pseudo_sum = ipv4_pseudo_sum(payload,
                                             ip->header->offset,
                                             tcp_protocol,
                                             static_cast<uint16_t>(tcp_len));
                set_l4_lengths(result.offload, *ip->header, ihl_bytes, tcp_header_len);
                result.offload.layer3 = OffloadLayer3::IPv4;
                has_pseudo_header = true;
            } else if (auto ipv6 = find_header(packet, registry, "IPv6")) {
                pseudo_sum = ipv6_pseudo_sum(payload,
                                             ipv6->header->offset,
                                             tcp_protocol,
                                             static_cast<uint32_t>(tcp_len));
                set_l4_lengths(result.offload, *ipv6->header, 40, tcp_header_len);
                result.offload.layer3 = OffloadLayer3::IPv6;
                has_pseudo_header = true;
            } else {
                result.errors.push_back("TCP checksum requires IPv4 or IPv6 header");
            }

            if (has_pseudo_header && options.tcp_checksum == FixupMode::Software) {
                write_u16(payload,
                          tcp->header->offset + 16,
                          internet_checksum(pseudo_sum + checksum_sum(payload.subspan(tcp->header->offset,
                                                                                      tcp_len))));
            } else if (has_pseudo_header && options.tcp_checksum == FixupMode::HardwareOffload) {
                set_l4_checksum_for_offload(payload, tcp->header->offset, pseudo_sum);
                result.offload.tcp_checksum = true;
            }
        }
    }

    if (auto icmp = find_header(packet, registry, "ICMP");
        icmp && options.icmp_checksum != FixupMode::Disabled) {
        if (packet_len < icmp->header->offset + 4) {
            result.errors.push_back("ICMP header extends beyond packet length");
        } else {
            write_u16(payload, icmp->header->offset + 2, 0);
            if (options.icmp_checksum == FixupMode::Software) {
                write_u16(payload,
                          icmp->header->offset + 2,
                          internet_checksum(checksum_sum(payload.subspan(icmp->header->offset,
                                                                         packet_len - icmp->header->offset))));
            } else if (options.icmp_checksum == FixupMode::HardwareOffload) {
                result.errors.push_back("ICMP hardware checksum offload is not supported");
            }
        }
    }

    result.ok = result.errors.empty();
    return result;
}

} // namespace packet
