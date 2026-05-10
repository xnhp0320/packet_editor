#include "packet/packet_constructor.hpp"
#include "packet/util.hpp"

#include <algorithm>
#include <format>
#include <limits>
#include <memory>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace packet {

namespace {

std::optional<ConstructorValue> construct_value(std::string_view type,
                                                size_t bit_width,
                                                const ValueType& value,
                                                std::string& error) {
    if (auto range_bit_width = bit_range_width_for_type_name(type)) {
        if (std::holds_alternative<int64_t>(value)) {
            if (auto bit_error = validate_bit_value(value, *range_bit_width)) {
                error = *bit_error;
                return std::nullopt;
            }
            return ConstructorValue{static_cast<uint64_t>(std::get<int64_t>(value))};
        }
        if (!std::holds_alternative<std::string>(value)) {
            error = "expected integer or string value";
            return std::nullopt;
        }

        const auto raw = trim_ascii_whitespace(std::get<std::string>(value));
        if (raw.starts_with('[') || raw.ends_with(']') || raw.find('-') != std::string_view::npos) {
            auto ranges = parse_uint_ranges(raw, *range_bit_width, error);
            if (!ranges) {
                return std::nullopt;
            }
            return ConstructorValue{*ranges};
        }

        auto scalar = parse_uint_value(raw, *range_bit_width, error);
        if (!scalar) {
            return std::nullopt;
        }
        return ConstructorValue{*scalar};
    }

    if (type.starts_with('b')) {
        if (!std::holds_alternative<int64_t>(value)) {
            error = "expected integer value";
            return std::nullopt;
        }
        auto integer = std::get<int64_t>(value);
        if (integer < 0) {
            error = "negative integer value";
            return std::nullopt;
        }
        if (auto bit_error = validate_bit_value(value, bit_width)) {
            error = *bit_error;
            return std::nullopt;
        }
        return ConstructorValue{static_cast<uint64_t>(integer)};
    }
    if (!std::holds_alternative<std::string>(value)) {
        error = std::format("{} value must be a string", type);
        return std::nullopt;
    }

    const auto& string = std::get<std::string>(value);
    if (type == "mac") {
        auto mac = MacAddr::parse(string);
        if (!mac) {
            error = std::format("invalid mac address '{}'", string);
            return std::nullopt;
        }
        return ConstructorValue{*mac};
    }
    if (type == "ipv4") {
        auto ip = IPv4::parse(string);
        if (!ip) {
            error = std::format("invalid ipv4 address '{}'", string);
            return std::nullopt;
        }
        return ConstructorValue{*ip};
    }
    if (type == "ipv6") {
        auto ip = IPv6::parse(string);
        if (!ip) {
            error = std::format("invalid ipv6 address '{}'", string);
            return std::nullopt;
        }
        return ConstructorValue{*ip};
    }
    if (type == "ipv4_range") {
        auto range = parse_ipv4_range(string, error);
        if (!range) {
            return std::nullopt;
        }
        return ConstructorValue{*range};
    }
    if (type == "ipv6_range") {
        auto range = parse_ipv6_range(string, error);
        if (!range) {
            return std::nullopt;
        }
        return ConstructorValue{*range};
    }
    if (type == "ipv4_ranges") {
        auto ranges = parse_ipv4_ranges(string, error);
        if (!ranges) {
            return std::nullopt;
        }
        return ConstructorValue{*ranges};
    }
    if (type == "ipv6_ranges") {
        auto ranges = parse_ipv6_ranges(string, error);
        if (!ranges) {
            return std::nullopt;
        }
        return ConstructorValue{*ranges};
    }

    error = std::format("unsupported constructor type '{}'", type);
    return std::nullopt;
}

std::optional<ConstructorValue> construct_value(const FieldSpec& field,
                                                const ValueType& value,
                                                std::string& error) {
    return construct_value(field.type_name, field.bit_width, value, error);
}

std::optional<ConstructorValue> construct_value(const OptionSpec& option,
                                                const ValueType& value,
                                                std::string& error) {
    return construct_value(option.type_name, bit_width_for_type_name(option.type_name), value, error);
}

std::optional<ValueType> scalar_attribute_value(const Attribute& attr, std::string& error) {
    if (!attr.value) {
        error = "requires a value";
        return std::nullopt;
    }

    auto value = evaluate(**attr.value);
    if (std::holds_alternative<std::string>(value)) {
        return ValueType{std::get<std::string>(std::move(value))};
    }
    if (std::holds_alternative<int64_t>(value)) {
        return ValueType{std::get<int64_t>(value)};
    }

    error = "requires a scalar value";
    return std::nullopt;
}

std::optional<Packet> packet_attribute_value(const Attribute& attr, std::string& error) {
    if (!attr.value) {
        error = "requires a value";
        return std::nullopt;
    }

    auto value = evaluate(**attr.value);
    if (!std::holds_alternative<Packet>(value)) {
        error = "requires a packet value";
        return std::nullopt;
    }
    return std::get<Packet>(std::move(value));
}

const ConstructorValue* scalar_option_value(const OptionConstructor& option) {
    if (!std::holds_alternative<ConstructorValue>(option.value)) {
        return nullptr;
    }
    return &std::get<ConstructorValue>(option.value);
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

size_t packet_option_bit_width(const OptionConstructor& option, const Registry& registry) {
    if (!std::holds_alternative<std::shared_ptr<PacketConstructor>>(option.value)) {
        return 0;
    }
    const auto& packet = *std::get<std::shared_ptr<PacketConstructor>>(option.value);
    const auto bit_width = packet_bit_width(packet, registry);
    return ((bit_width + 31) / 32) * 32;
}

FieldConstructor* find_field(HeaderConstructor& header, std::string_view name);

size_t header_option_bit_width(HeaderConstructor& header,
                               const Registry& registry,
                               PacketConstructorBuilder::Result& result) {
    const auto option_it = std::ranges::find_if(header.options, [](const OptionConstructor& option) {
        return option.name == "options" &&
               std::holds_alternative<std::shared_ptr<PacketConstructor>>(option.value);
    });
    if (option_it == header.options.end()) {
        return 0;
    }
    if (header.protocol != "IP" && header.protocol != "TCP") {
        result.errors.push_back(std::format("packet-valued option '{}.{}' is not serializable",
                                            header.protocol,
                                            option_it->name));
        return 0;
    }

    constexpr size_t base_header_bytes = 20;
    const auto option_bits = packet_option_bit_width(*option_it, registry);
    const auto header_bytes = base_header_bytes + option_bits / 8;
    if (header_bytes > 60) {
        result.errors.push_back(std::format("{} header with options is {} bytes but maximum is 60",
                                            header.protocol,
                                            header_bytes));
        return 0;
    }

    const auto words = static_cast<uint64_t>(header_bytes / 4);
    const auto field_name = header.protocol == "IP" ? std::string_view{"ihl"} : std::string_view{"dataofs"};
    auto* length_field = find_field(header, field_name);
    if (!length_field) {
        result.errors.push_back(std::format("{} header is missing {} field",
                                            header.protocol,
                                            field_name));
        return 0;
    }
    if (length_field->explicitly_set) {
        if (!std::holds_alternative<uint64_t>(length_field->value) ||
            std::get<uint64_t>(length_field->value) != words) {
            result.errors.push_back(std::format("explicit '{}.{}' does not match option header length {} words",
                                                header.protocol,
                                                field_name,
                                                words));
        }
    } else {
        length_field->value = ConstructorValue{words};
    }
    return option_bits;
}

FieldConstructor* find_field(HeaderConstructor& header, std::string_view name) {
    auto it = std::ranges::find_if(header.fields, [name](const FieldConstructor& field) {
        return field.name == name;
    });
    if (it == header.fields.end()) {
        return nullptr;
    }
    return &*it;
}

OptionConstructor* find_option(HeaderConstructor& header, std::string_view name) {
    auto it = std::ranges::find_if(header.options, [name](const OptionConstructor& option) {
        return option.name == name;
    });
    if (it == header.options.end()) {
        return nullptr;
    }
    return &*it;
}

std::optional<uint64_t> integer_option_value(const HeaderConstructor& header,
                                             const OptionConstructor& option,
                                             PacketConstructorBuilder::Result& result) {
    const auto* value = scalar_option_value(option);
    if (value && std::holds_alternative<uint64_t>(*value)) {
        return std::get<uint64_t>(*value);
    }
    result.errors.push_back(std::format("option '{}.{}' is not an integer value",
                                        header.protocol,
                                        option.name));
    return std::nullopt;
}

size_t payload_bit_width(HeaderConstructor& header,
                         size_t packet_bit_offset,
                         PacketConstructorBuilder::Result& result) {
    if (header.protocol != "Payload") {
        return 0;
    }

    auto* length = find_option(header, "length");
    auto* total_length = find_option(header, "total_length");
    if (!length) {
        result.errors.push_back("Payload header is missing length option");
        return 0;
    }

    if (total_length && total_length->explicitly_set) {
        if (length->explicitly_set) {
            result.errors.push_back("Payload length and total_length cannot both be explicitly set");
            return 0;
        }

        const auto total_bytes = integer_option_value(header, *total_length, result);
        if (!total_bytes) {
            return 0;
        }
        const auto prefix_bytes = packet_bit_offset / 8;
        if (*total_bytes < prefix_bytes) {
            result.errors.push_back(std::format(
                "Payload total_length {} is smaller than preceding header length {}",
                *total_bytes,
                prefix_bytes));
            return 0;
        }

        const auto payload_bytes = *total_bytes - prefix_bytes;
        if (payload_bytes > std::numeric_limits<size_t>::max() / 8) {
            result.errors.push_back(std::format("Payload length {} is too large", payload_bytes));
            return 0;
        }
        length->value = ConstructorValue{payload_bytes};
        return static_cast<size_t>(payload_bytes) * 8;
    }

    const auto length_bytes = integer_option_value(header, *length, result);
    if (!length_bytes) {
        return 0;
    }
    if (*length_bytes > std::numeric_limits<size_t>::max() / 8) {
        result.errors.push_back(std::format("Payload length {} is too large", *length_bytes));
        return 0;
    }
    return static_cast<size_t>(*length_bytes) * 8;
}

void apply_inference_rules(PacketConstructor& constructor,
                           const Registry& registry,
                           PacketConstructorBuilder::Result& result) {
    if (constructor.size() < 2) {
        return;
    }

    for (auto parent = constructor.begin(); parent + 1 != constructor.end(); ++parent) {
        const auto& child = *(parent + 1);
        const auto* rules = registry.find_inference_rules(parent->protocol, child.protocol);
        if (!rules) {
            continue;
        }

        for (const auto& rule : *rules) {
            auto* target = find_field(*parent, rule.target_field);
            if (!target) {
                result.errors.push_back(std::format(
                    "inference rule '{}'/'{}' targets unknown field '{}.{}'",
                    rule.parent_header,
                    rule.child_header,
                    parent->protocol,
                    rule.target_field));
                continue;
            }

            if (target->explicitly_set) {
                if (target->value != rule.value) {
                    result.warnings.push_back(std::format(
                        "explicit '{}.{}' overrides inference from next header '{}'",
                        parent->protocol,
                        rule.target_field,
                        child.protocol));
                }
                continue;
            }

            target->value = rule.value;
        }
    }
}

} // namespace

PacketConstructorBuilder::PacketConstructorBuilder(const Registry& registry)
    : registry_(registry)
{
}

PacketConstructorBuilder::Result PacketConstructorBuilder::build(const Packet& packet) const {
    Result result;
    PacketConstructor constructor;
    size_t packet_bit_offset = 0;

    for (const auto& header : packet) {
        const auto* header_spec = registry_.find_header(header.protocol);
        if (!header_spec) {
            result.errors.push_back(std::format("unknown header: '{}'", header.protocol));
            continue;
        }
        if (packet_bit_offset % 8 != 0) {
            result.errors.push_back(std::format("header '{}' starts at non-byte offset {}",
                                                header.protocol, packet_bit_offset));
            continue;
        }

        std::unordered_map<std::string_view, const Attribute*> attrs;
        for (const auto& attr : header.attributes) {
            if (attrs.contains(attr.name)) {
                result.errors.push_back(std::format("duplicate attribute '{}' in header '{}'",
                                                    attr.name, header.protocol));
                continue;
            }
            attrs.emplace(attr.name, &attr);
        }

        HeaderConstructor header_constructor{
            header.protocol,
            packet_bit_offset / 8,
            {},
            {},
        };
        header_constructor.fields.reserve(header_spec->fields.size());
        header_constructor.options.reserve(header_spec->options.size());

        for (const auto& field : header_spec->fields) {
            auto attr_it = attrs.find(field.name);
            if (attr_it == attrs.end()) {
                header_constructor.fields.push_back(FieldConstructor{
                    field.name,
                    field.default_value,
                    false,
                });
                continue;
            }

            const auto& attr = *attr_it->second;
            std::string error;
            auto attr_value = scalar_attribute_value(attr, error);
            if (!attr_value) {
                result.errors.push_back(std::format("attribute '{}' in header '{}' {}",
                                                    attr.name, header.protocol, error));
                continue;
            }

            auto value = construct_value(field, *attr_value, error);
            if (!value) {
                result.errors.push_back(std::format("invalid '{}' in header '{}': {}",
                                                    attr.name, header.protocol, error));
                continue;
            }
            header_constructor.fields.push_back(FieldConstructor{
                field.name,
                std::move(*value),
                true,
            });
        }

        for (const auto& option : header_spec->options) {
            auto attr_it = attrs.find(option.name);
            if (attr_it == attrs.end()) {
                if (option.default_value) {
                    header_constructor.options.push_back(OptionConstructor{
                        option.name,
                        *option.default_value,
                        false,
                    });
                }
                continue;
            }

            const auto& attr = *attr_it->second;
            if (option.value_kind == AttrValueKind::Packet) {
                std::string error;
                auto packet_value = packet_attribute_value(attr, error);
                if (!packet_value) {
                    result.errors.push_back(std::format("attribute '{}' in header '{}' {}",
                                                        attr.name, header.protocol, error));
                    continue;
                }

                auto nested = build(*packet_value);
                result.warnings.insert(result.warnings.end(),
                                       nested.warnings.begin(),
                                       nested.warnings.end());
                if (!nested.ok || !nested.packet) {
                    for (const auto& nested_error : nested.errors) {
                        result.errors.push_back(std::format("invalid packet option '{}.{}': {}",
                                                            header.protocol,
                                                            attr.name,
                                                            nested_error));
                    }
                    continue;
                }

                header_constructor.options.push_back(OptionConstructor{
                    option.name,
                    std::make_shared<PacketConstructor>(std::move(*nested.packet)),
                    true,
                });
            } else {
                std::string error;
                auto attr_value = scalar_attribute_value(attr, error);
                if (!attr_value) {
                    result.errors.push_back(std::format("attribute '{}' in header '{}' {}",
                                                        attr.name, header.protocol, error));
                    continue;
                }

                auto value = construct_value(option, *attr_value, error);
                if (!value) {
                    result.errors.push_back(std::format("invalid '{}' in header '{}': {}",
                                                        attr.name, header.protocol, error));
                    continue;
                }
                header_constructor.options.push_back(OptionConstructor{
                    option.name,
                    std::move(*value),
                    true,
                });
            }
        }

        for (const auto& [name, attr] : attrs) {
            auto known_field = std::ranges::any_of(header_spec->fields, [name](const FieldSpec& field) {
                return field.name == name;
            });
            auto known_option = std::ranges::any_of(header_spec->options, [name](const OptionSpec& option) {
                return option.name == name;
            });
            if (!known_field && !known_option) {
                result.errors.push_back(std::format("unknown attribute '{}' in header '{}'",
                                                    name, header.protocol));
            }
        }

        const auto option_bit_width = header_option_bit_width(header_constructor, registry_, result);

        constructor.push_back(std::move(header_constructor));
        packet_bit_offset += header_spec->bit_width + option_bit_width;
        if (packet_bit_offset % 8 == 0) {
            packet_bit_offset += payload_bit_width(constructor.back(), packet_bit_offset, result);
        }
    }

    if (!result.errors.empty()) {
        result.ok = false;
        return result;
    }

    apply_inference_rules(constructor, registry_, result);

    if (!result.errors.empty()) {
        result.ok = false;
        return result;
    }

    result.ok = true;
    result.packet = std::move(constructor);
    return result;
}

} // namespace packet
