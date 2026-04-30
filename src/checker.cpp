#include "packet/checker.hpp"

#include <cstdlib>
#include <format>
#include <iostream>
#include <utility>

namespace packet {

namespace {

template <size_t... Is>
void register_bit_types(Checker& checker, std::index_sequence<Is...>) {
    (checker.register_type(std::format("b{}", Is + 1),
                           std::make_unique<BitsValidator<Is + 1>>()), ...);
}

} // namespace

Checker::Checker() {
    register_type("mac", std::make_unique<MacAddrValidator>());
    register_type("ipv4", std::make_unique<IPv4Validator>());
    register_type("ipv6", std::make_unique<IPv6Validator>());

    register_type("ipv4_range", std::make_unique<RangeValidator<IPv4Validator, 32>>());
    register_type("ipv6_range", std::make_unique<RangeValidator<IPv6Validator, 128>>());
    register_type("ipv4_ranges", std::make_unique<RangeListValidator<IPv4Validator, 32>>());
    register_type("ipv6_ranges", std::make_unique<RangeListValidator<IPv6Validator, 128>>());

    register_bit_types(*this, std::make_index_sequence<64>{});

    register_header("Ether", {
        {"dst", "mac"},
        {"src", "mac"},
        {"type", "b16"},
    });

    register_header("IP", {
        {"version", "b4"},
        {"ihl",     "b4"},
        {"tos",     "b8"},
        {"len",     "b16"},
        {"id",      "b16"},
        {"flags",   "b3"},
        {"frag",    "b13"},
        {"ttl",     "b8"},
        {"proto",   "b8"},
        {"src",     "ipv4_ranges"},
        {"dst",     "ipv4_ranges"},
        {"chksum",  "b16"},
    });

    register_header("IPv6", {
        {"version", "b4"},
        {"tc",      "b8"},
        {"fl",      "b20"},
        {"len",     "b16"},
        {"nh",      "b8"},
        {"hlim",    "b8"},
        {"src",     "ipv6_ranges"},
        {"dst",     "ipv6_ranges"},
    });

    register_header("TCP", {
        {"sport",    "b16"},
        {"dport",    "b16"},
        {"seq",      "b32"},
        {"ack",      "b32"},
        {"dataofs",  "b4"},
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
        {"flags",     "b8"},
        {"reserved",  "b24"},
        {"vni",       "b24"},
        {"reserved2", "b8"},
    });
}

Checker& Checker::register_type(std::string type_name, std::unique_ptr<TypeValidator> validator) {
    type_validators_[std::move(type_name)] = std::move(validator);
    return *this;
}

Checker& Checker::register_header(std::string protocol, std::vector<AttrSpec> attrs) {
    auto& names = attr_names_[protocol];
    auto& types = attr_types_[protocol];
    for (auto& attr : attrs) {
        names.insert(attr.name);
        if (attr.type_name) {
            types[attr.name] = *attr.type_name;
        }
    }
    return *this;
}

Checker::Result Checker::check(const Packet& packet) const {
    Result result{true, {}, {}};

    for (const auto& header : packet) {
        auto it = attr_names_.find(header.protocol);
        if (it == attr_names_.end()) {
            result.errors.push_back(
                std::format("unknown header: '{}'", header.protocol));
            result.ok = false;
            continue;
        }

        const auto& valid_attrs = it->second;
        auto type_it = attr_types_.find(header.protocol);

        for (const auto& attr : header.attributes) {
            if (!valid_attrs.contains(attr.name)) {
                result.warnings.push_back(
                    std::format("unknown attribute '{}' in header '{}'",
                                attr.name, header.protocol));
                continue;
            }

            if (attr.value.has_value() && type_it != attr_types_.end()) {
                auto type_name_it = type_it->second.find(attr.name);
                if (type_name_it != type_it->second.end()) {
                    auto validator_it = type_validators_.find(type_name_it->second);
                    if (validator_it != type_validators_.end()) {
                        auto err = validator_it->second->validate(*attr.value);
                        if (err) {
                            result.errors.push_back(
                                std::format("invalid '{}' in header '{}': {}",
                                            attr.name, header.protocol, *err));
                            result.ok = false;
                        }
                    }
                }
            }
        }
    }

    return result;
}

void Checker::validate_or_exit(const Packet& packet) const {
    auto result = check(packet);

    for (const auto& w : result.warnings) {
        std::cerr << "WARNING: " << w << std::endl;
    }
    for (const auto& e : result.errors) {
        std::cerr << "ERROR: " << e << std::endl;
    }

    if (!result.ok) {
        std::exit(1);
    }

    if (!result.warnings.empty()) {
        std::cerr << std::format("{} warning(s) found.", result.warnings.size()) << std::endl;
    }
}

} // namespace packet
