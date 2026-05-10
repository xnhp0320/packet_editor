#include "packet/registry.hpp"
#include "packet/util.hpp"

#include <algorithm>
#include <format>
#include <stdexcept>
#include <utility>

namespace packet {

namespace {

template <size_t... Is>
void register_bit_types(Registry& registry, std::index_sequence<Is...>) {
    ((registry.register_type(std::format("b{}", Is + 1),
                             std::make_unique<BitsValidator<Is + 1>>())
              .register_type(std::format("b{}_ranges", Is + 1),
                             std::make_unique<BitRangeListValidator<Is + 1>>())), ...);
}

} // namespace

std::optional<std::string> validate_constructor_value(std::string_view,
                                                      std::string_view type_name,
                                                      const ConstructorValue& value) {
    const auto type = type_name;
    const auto bit_width = bit_width_for_type_name(type);
    auto integer_fits = [](uint64_t integer, size_t bit_width) -> std::optional<std::string> {
        if (bit_width < 64 && integer > ((uint64_t{1} << bit_width) - 1)) {
            return std::format("value {} does not fit in {} bits", integer, bit_width);
        }
        return std::nullopt;
    };

    if (auto range_bit_width = bit_range_width_for_type_name(type)) {
        if (!std::holds_alternative<uint64_t>(value)) {
            if (!std::holds_alternative<std::vector<UIntRange>>(value)) {
                return std::string{"bit range constructor fields require integer or range list values"};
            }
            const auto& ranges = std::get<std::vector<UIntRange>>(value);
            for (const auto& range : ranges) {
                if (range.first > range.last) {
                    return std::format("range {}-{} has first value greater than last value",
                                       range.first,
                                       range.last);
                }
                if (auto error = integer_fits(range.first, *range_bit_width)) {
                    return error;
                }
                if (auto error = integer_fits(range.last, *range_bit_width)) {
                    return error;
                }
            }
            return std::nullopt;
        }
        return integer_fits(std::get<uint64_t>(value), *range_bit_width);
    }

    if (type.starts_with('b')) {
        if (!std::holds_alternative<uint64_t>(value)) {
            return std::string{"bit constructor fields require integer values"};
        }
        return integer_fits(std::get<uint64_t>(value), bit_width);
    }
    if (type == "mac") {
        if (std::holds_alternative<MacAddr>(value)) {
            return std::nullopt;
        }
        return std::string{"mac constructor fields require mac address values"};
    }
    if (type == "ipv4") {
        if (std::holds_alternative<IPv4>(value)) {
            return std::nullopt;
        }
        return std::string{"ipv4 constructor fields require ipv4 address values"};
    }
    if (type == "ipv6") {
        if (std::holds_alternative<IPv6>(value)) {
            return std::nullopt;
        }
        return std::string{"ipv6 constructor fields require ipv6 address values"};
    }
    if (type == "ipv4_range") {
        if (std::holds_alternative<IPv4Range>(value)) {
            return std::nullopt;
        }
        return std::string{"ipv4 range constructor fields require ipv4 range values"};
    }
    if (type == "ipv6_range") {
        if (std::holds_alternative<IPv6Range>(value)) {
            return std::nullopt;
        }
        return std::string{"ipv6 range constructor fields require ipv6 range values"};
    }
    if (type == "ipv4_ranges") {
        if (std::holds_alternative<std::vector<IPv4Range>>(value)) {
            return std::nullopt;
        }
        return std::string{"ipv4 ranges constructor fields require ipv4 range list values"};
    }
    if (type == "ipv6_ranges") {
        if (std::holds_alternative<std::vector<IPv6Range>>(value)) {
            return std::nullopt;
        }
        return std::string{"ipv6 ranges constructor fields require ipv6 range list values"};
    }

    return std::format("unsupported constructor type '{}'", type);
}

Registry::Registry() {
    register_type("mac", std::make_unique<MacAddrValidator>());
    register_type("ipv4", std::make_unique<IPv4Validator>());
    register_type("ipv6", std::make_unique<IPv6Validator>());

    register_type("ipv4_range", std::make_unique<IPv4RangeValidator>());
    register_type("ipv6_range", std::make_unique<IPv6RangeValidator>());
    register_type("ipv4_ranges", std::make_unique<IPv4RangeListValidator>());
    register_type("ipv6_ranges", std::make_unique<IPv6RangeListValidator>());

    register_bit_types(*this, std::make_index_sequence<64>{});

    register_header("Ether", {
        {"dst", "mac"},
        {"src", "mac"},
        {"type", "b16"},
    });

    register_header("IP", {
        {"version", "b4", ConstructorValue{uint64_t{4}}},
        {"ihl",     "b4", ConstructorValue{uint64_t{5}}},
        {"tos",     "b8"},
        {"len",     "b16"},
        {"id",      "b16"},
        {"flags",   "b3"},
        {"frag",    "b13"},
        {"ttl",     "b8", ConstructorValue{uint64_t{64}}},
        {"proto",   "b8"},
        {"chksum",  "b16"},
        {"src",     "ipv4_ranges"},
        {"dst",     "ipv4_ranges"},
    }, {
        {"options", "", std::nullopt, AttrValueKind::Packet},
    });

    register_header("IPv6", {
        {"version", "b4", ConstructorValue{uint64_t{6}}},
        {"tc",      "b8"},
        {"fl",      "b20"},
        {"len",     "b16"},
        {"nh",      "b8"},
        {"hlim",    "b8", ConstructorValue{uint64_t{64}}},
        {"src",     "ipv6_ranges"},
        {"dst",     "ipv6_ranges"},
    });

    register_header("TCP", {
        {"sport",    "b16_ranges"},
        {"dport",    "b16_ranges"},
        {"seq",      "b32"},
        {"ack",      "b32"},
        {"dataofs",  "b4", ConstructorValue{uint64_t{5}}},
        {"reserved", "b3"},
        {"flags",    "b9"},
        {"window",   "b16"},
        {"chksum",   "b16"},
        {"urgptr",   "b16"},
    }, {
        {"options", "", std::nullopt, AttrValueKind::Packet},
    });

    register_header("UDP", {
        {"sport",  "b16_ranges"},
        {"dport",  "b16_ranges"},
        {"len",    "b16"},
        {"chksum", "b16"},
    });

    register_header("ICMP", {
        {"type",   "b8"},
        {"code",   "b8"},
        {"chksum", "b16"},
        {"id",     "b16"},
        {"seq",    "b16"},
    });

    register_header("VLAN", {
        {"prio", "b3"},
        {"dei",  "b1"},
        {"vlan", "b12"},
        {"type", "b16"},
    });

    register_header("VXLAN", {
        {"flags",     "b8", ConstructorValue{uint64_t{0x08}}},
        {"reserved",  "b24"},
        {"vni",       "b24"},
        {"reserved2", "b8"},
    });

    register_header("Payload", {}, {
        {"length",       "b64", ConstructorValue{uint64_t{0}}},
        {"total_length", "b64"},
    });

    register_header("IPOption_EOL", {
        {"type", "b8", ConstructorValue{uint64_t{0}}},
    });
    register_header("IPOption_NOP", {
        {"type", "b8", ConstructorValue{uint64_t{1}}},
    });
    register_header("TCPOption_EOL", {
        {"kind", "b8", ConstructorValue{uint64_t{0}}},
    });
    register_header("TCPOption_NOP", {
        {"kind", "b8", ConstructorValue{uint64_t{1}}},
    });
    register_header("TCPOption_MSS", {
        {"kind",   "b8",  ConstructorValue{uint64_t{2}}},
        {"length", "b8",  ConstructorValue{uint64_t{4}}},
        {"value",  "b16"},
    });
    register_header("TCPOption_WS", {
        {"kind",   "b8", ConstructorValue{uint64_t{3}}},
        {"length", "b8", ConstructorValue{uint64_t{3}}},
        {"shift",  "b8"},
    });
    register_header("TCPOption_SACKPermitted", {
        {"kind",   "b8", ConstructorValue{uint64_t{4}}},
        {"length", "b8", ConstructorValue{uint64_t{2}}},
    });
    register_header("TCPOption_Timestamp", {
        {"kind",    "b8",  ConstructorValue{uint64_t{8}}},
        {"length",  "b8",  ConstructorValue{uint64_t{10}}},
        {"tsval",   "b32"},
        {"tsecr",   "b32"},
    });

    register_inference_rule("Ether", "IP", "type", ConstructorValue{uint64_t{0x0800}});
    register_inference_rule("Ether", "IPv6", "type", ConstructorValue{uint64_t{0x86dd}});
    register_inference_rule("Ether", "VLAN", "type", ConstructorValue{uint64_t{0x8100}});
    register_inference_rule("VLAN", "IP", "type", ConstructorValue{uint64_t{0x0800}});
    register_inference_rule("VLAN", "IPv6", "type", ConstructorValue{uint64_t{0x86dd}});
    register_inference_rule("IP", "TCP", "proto", ConstructorValue{uint64_t{6}});
    register_inference_rule("IP", "UDP", "proto", ConstructorValue{uint64_t{17}});
    register_inference_rule("IP", "ICMP", "proto", ConstructorValue{uint64_t{1}});
    register_inference_rule("IPv6", "TCP", "nh", ConstructorValue{uint64_t{6}});
    register_inference_rule("IPv6", "UDP", "nh", ConstructorValue{uint64_t{17}});
    register_inference_rule("IPv6", "ICMP", "nh", ConstructorValue{uint64_t{58}});
    register_inference_rule("UDP", "VXLAN", "dport", ConstructorValue{uint64_t{4789}});
}

Registry& Registry::register_type(std::string type_name, std::unique_ptr<TypeValidator> validator) {
    type_validators_[std::move(type_name)] = std::move(validator);
    return *this;
}

Registry& Registry::register_header(std::string protocol,
                                    std::vector<AttrSpec> fields,
                                    std::vector<AttrSpec> options) {
    auto& names = attr_names_[protocol];
    auto& types = attr_types_[protocol];
    names.clear();
    types.clear();
    HeaderSpec header_spec{protocol, {}, {}, 0};
    for (auto& attr : fields) {
        names.insert(attr.name);
        types[attr.name] = attr.type_name;
        auto bit_width = bit_width_for_type_name(attr.type_name);
        auto field = FieldSpec{
            attr.name,
            attr.type_name,
            header_spec.bit_width,
            bit_width,
            attr.default_value.value_or(default_constructor_value_for_type(attr.type_name)),
        };
        if (auto error = validate_constructor_value(field.name, field.type_name, field.default_value)) {
            throw std::invalid_argument(std::format("invalid default value for '{}.{}': {}",
                                                    protocol,
                                                    field.name,
                                                    *error));
        }
        header_spec.fields.push_back(std::move(field));
        header_spec.bit_width += bit_width;
    }
    for (auto& attr : options) {
        names.insert(attr.name);
        if (attr.value_kind == AttrValueKind::Scalar) {
            types[attr.name] = attr.type_name;
        }
        auto option = OptionSpec{
            attr.name,
            attr.type_name,
            attr.value_kind,
            attr.default_value,
        };
        if (option.value_kind == AttrValueKind::Packet && option.default_value) {
            throw std::invalid_argument(std::format("packet option '{}.{}' cannot have scalar default value",
                                                    protocol,
                                                    option.name));
        }
        if (option.value_kind == AttrValueKind::Scalar && option.default_value) {
            if (auto error = validate_constructor_value(option.name,
                                                        option.type_name,
                                                        *option.default_value)) {
                throw std::invalid_argument(std::format("invalid default value for '{}.{}': {}",
                                                        protocol,
                                                        option.name,
                                                        *error));
            }
        }
        header_spec.options.push_back(std::move(option));
    }
    header_specs_[protocol] = std::move(header_spec);
    return *this;
}

Registry& Registry::register_inference_rule(std::string parent_header,
                                            std::string child_header,
                                            std::string target_field,
                                            ConstructorValue value) {
    const auto* parent_spec = find_header(parent_header);
    if (!parent_spec) {
        throw std::invalid_argument(std::format("inference parent header '{}' is not registered",
                                                parent_header));
    }
    if (!find_header(child_header)) {
        throw std::invalid_argument(std::format("inference child header '{}' is not registered",
                                                child_header));
    }
    auto target_it = std::ranges::find_if(parent_spec->fields, [&target_field](const FieldSpec& field) {
        return field.name == target_field;
    });
    if (target_it == parent_spec->fields.end()) {
        throw std::invalid_argument(std::format("inference rule '{}'/'{}' targets unknown field '{}.{}'",
                                                parent_header,
                                                child_header,
                                                parent_header,
                                                target_field));
    }
    if (auto error = validate_constructor_value(target_it->name, target_it->type_name, value)) {
        throw std::invalid_argument(std::format(
            "inference rule '{}'/'{}' has invalid value for '{}.{}': {}",
            parent_header,
            child_header,
            parent_header,
            target_field,
            *error));
    }

    auto& rules = inference_rules_[parent_header][child_header];
    rules.push_back(InferenceRule{
        std::move(parent_header),
        std::move(child_header),
        std::move(target_field),
        std::move(value),
    });
    return *this;
}

const TypeRegistry& Registry::type_validators() const {
    return type_validators_;
}

const AttrNameRegistry& Registry::attr_names() const {
    return attr_names_;
}

const AttrTypeRegistry& Registry::attr_types() const {
    return attr_types_;
}

const HeaderSpecRegistry& Registry::header_specs() const {
    return header_specs_;
}

const HeaderSpec* Registry::find_header(std::string_view protocol) const {
    auto it = header_specs_.find(std::string{protocol});
    if (it == header_specs_.end()) {
        return nullptr;
    }
    return &it->second;
}

const std::vector<InferenceRule>* Registry::find_inference_rules(std::string_view parent_header,
                                                                 std::string_view child_header) const {
    auto parent_it = inference_rules_.find(std::string{parent_header});
    if (parent_it == inference_rules_.end()) {
        return nullptr;
    }
    auto child_it = parent_it->second.find(std::string{child_header});
    if (child_it == parent_it->second.end()) {
        return nullptr;
    }
    return &child_it->second;
}

} // namespace packet
