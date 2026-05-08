#include "packet/registry.hpp"
#include "packet/util.hpp"

#include <format>
#include <utility>

namespace packet {

namespace {

template <size_t... Is>
void register_bit_types(Registry& registry, std::index_sequence<Is...>) {
    (registry.register_type(std::format("b{}", Is + 1),
                            std::make_unique<BitsValidator<Is + 1>>()), ...);
}

} // namespace

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
        {"src",     "ipv4_ranges"},
        {"dst",     "ipv4_ranges"},
        {"chksum",  "b16"},
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
        {"sport",    "b16"},
        {"dport",    "b16"},
        {"seq",      "b32"},
        {"ack",      "b32"},
        {"dataofs",  "b4", ConstructorValue{uint64_t{5}}},
        {"reserved", "b3"},
        {"flags",    "b9"},
        {"window",   "b16"},
        {"chksum",   "b16"},
        {"urgptr",   "b16"},
    });

    register_header("UDP", {
        {"sport",  "b16"},
        {"dport",  "b16"},
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

    register_header("VXLAN", {
        {"flags",     "b8", ConstructorValue{uint64_t{0x08}}},
        {"reserved",  "b24"},
        {"vni",       "b24"},
        {"reserved2", "b8"},
    });
}

Registry& Registry::register_type(std::string type_name, std::unique_ptr<TypeValidator> validator) {
    type_validators_[std::move(type_name)] = std::move(validator);
    return *this;
}

Registry& Registry::register_header(std::string protocol, std::vector<AttrSpec> attrs) {
    auto& names = attr_names_[protocol];
    auto& types = attr_types_[protocol];
    names.clear();
    types.clear();
    HeaderSpec header_spec{protocol, {}, 0};
    for (auto& attr : attrs) {
        names.insert(attr.name);
        auto bit_width = bit_width_for_type_name(attr.type_name);
        header_spec.fields.push_back(FieldSpec{
            attr.name,
            attr.type_name,
            header_spec.bit_width,
            bit_width,
            attr.default_value.value_or(default_constructor_value_for_type(attr.type_name)),
        });
        header_spec.bit_width += bit_width;
        if (attr.type_name) {
            types[attr.name] = *attr.type_name;
        }
    }
    header_specs_[protocol] = std::move(header_spec);
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

} // namespace packet
