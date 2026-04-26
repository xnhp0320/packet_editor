#include "packet/checker.hpp"

#include <cstdlib>
#include <format>
#include <iostream>

namespace packet {

Checker::Checker() {
    register_type("mac", std::make_unique<MacAddrValidator>());
    register_type("ipv4", std::make_unique<IPv4Validator>());
    register_type("ipv6", std::make_unique<IPv6Validator>());

    register_header("Ether", {
        {"dst", "mac"},
        {"src", "mac"},
        {"type", std::nullopt},
    });

    register_header("IP", {
        {"version", std::nullopt},
        {"ihl", std::nullopt},
        {"tos", std::nullopt},
        {"len", std::nullopt},
        {"id", std::nullopt},
        {"flags", std::nullopt},
        {"frag", std::nullopt},
        {"ttl", std::nullopt},
        {"proto", std::nullopt},
        {"src", "ipv4"},
        {"dst", "ipv4"},
        {"chksum", std::nullopt},
    });

    register_header("IPv6", {
        {"version", std::nullopt},
        {"tc", std::nullopt},
        {"fl", std::nullopt},
        {"len", std::nullopt},
        {"nh", std::nullopt},
        {"hlim", std::nullopt},
        {"src", "ipv6"},
        {"dst", "ipv6"},
    });

    register_header("TCP", {
        {"sport", std::nullopt},
        {"dport", std::nullopt},
        {"seq", std::nullopt},
        {"ack", std::nullopt},
        {"dataofs", std::nullopt},
        {"reserved", std::nullopt},
        {"flags", std::nullopt},
        {"window", std::nullopt},
        {"chksum", std::nullopt},
        {"urgptr", std::nullopt},
    });

    register_header("UDP", {
        {"sport", std::nullopt},
        {"dport", std::nullopt},
        {"len", std::nullopt},
        {"chksum", std::nullopt},
    });

    register_header("ICMP", {
        {"type", std::nullopt},
        {"code", std::nullopt},
        {"chksum", std::nullopt},
        {"id", std::nullopt},
        {"seq", std::nullopt},
    });

    register_header("VXLAN", {
        {"flags", std::nullopt},
        {"reserved", std::nullopt},
        {"vni", std::nullopt},
        {"reserved2", std::nullopt},
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
