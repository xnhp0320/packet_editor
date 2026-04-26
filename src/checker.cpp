#include "packet/checker.hpp"

#include <cstdlib>
#include <format>
#include <iostream>

namespace packet {

Checker::Checker() {
    register_header("Ether", {"dst", "src", "type"});

    register_header("IP", {
        "version", "ihl", "tos", "len", "id",
        "flags", "frag", "ttl", "proto", "src",
        "dst", "chksum"
    });

    register_header("IPv6", {
        "version", "tc", "fl", "len", "nh",
        "hlim", "src", "dst"
    });

    register_header("TCP", {
        "sport", "dport", "seq", "ack", "dataofs",
        "reserved", "flags", "window", "chksum", "urgptr"
    });

    register_header("UDP", {
        "sport", "dport", "len", "chksum"
    });

    register_header("ICMP", {
        "type", "code", "chksum", "id", "seq"
    });

    register_header("VXLAN", {
        "flags", "reserved", "vni", "reserved2"
    });
}

Checker& Checker::register_header(std::string protocol, std::vector<std::string> known_attrs) {
    known_headers_[protocol] = std::unordered_set<std::string>(
        std::make_move_iterator(known_attrs.begin()),
        std::make_move_iterator(known_attrs.end()));
    return *this;
}

Checker::Result Checker::check(const Packet& packet) const {
    Result result{true, {}, {}};

    for (const auto& header : packet) {
        auto it = known_headers_.find(header.protocol);
        if (it == known_headers_.end()) {
            result.errors.push_back(
                std::format("unknown header: '{}'", header.protocol));
            result.ok = false;
            continue;
        }

        const auto& valid_attrs = it->second;
        for (const auto& attr : header.attributes) {
            if (!valid_attrs.contains(attr.name)) {
                result.warnings.push_back(
                    std::format("unknown attribute '{}' in header '{}'",
                                attr.name, header.protocol));
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
