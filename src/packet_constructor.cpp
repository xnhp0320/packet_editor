#include "packet/packet_constructor.hpp"
#include "packet/util.hpp"

#include <algorithm>
#include <format>
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

FieldConstructor* find_field(HeaderConstructor& header, std::string_view name) {
    auto it = std::ranges::find_if(header.fields, [name](const FieldConstructor& field) {
        return field.name == name;
    });
    if (it == header.fields.end()) {
        return nullptr;
    }
    return &*it;
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
            if (!attr.value) {
                result.errors.push_back(std::format("attribute '{}' in header '{}' requires a value",
                                                    attr.name, header.protocol));
                continue;
            }

            std::string error;
            auto value = construct_value(field, *attr.value, error);
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
            if (!attr.value) {
                result.errors.push_back(std::format("attribute '{}' in header '{}' requires a value",
                                                    attr.name, header.protocol));
                continue;
            }

            std::string error;
            auto value = construct_value(option, *attr.value, error);
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

        constructor.push_back(std::move(header_constructor));
        packet_bit_offset += header_spec->bit_width;
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
