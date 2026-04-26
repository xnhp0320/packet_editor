#include "packet/value.hpp"

#include <algorithm>
#include <cctype>
#include <format>

namespace packet {

static int hex_val(char c) {
    auto uc = static_cast<unsigned char>(c);
    if (std::isdigit(uc)) return uc - '0';
    if (uc >= 'a' && uc <= 'f') return uc - 'a' + 10;
    if (uc >= 'A' && uc <= 'F') return uc - 'A' + 10;
    return -1;
}

std::optional<MacAddr> MacAddr::parse(std::string_view s) {
    if (s.size() != 17) return std::nullopt;

    std::array<uint8_t, 6> bytes;
    for (size_t i = 0; i < 6; ++i) {
        size_t base = i * 3;
    int high = hex_val(s[base]);
        int low = hex_val(s[base + 1]);
        if (high < 0 || low < 0) return std::nullopt;
        if (i < 5 && s[base + 2] != ':') return std::nullopt;
        bytes[i] = static_cast<uint8_t>((high << 4) | low);
    }
    return MacAddr{bytes};
}

std::string MacAddr::to_string() const {
    return std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                       bytes_[0], bytes_[1], bytes_[2],
                       bytes_[3], bytes_[4], bytes_[5]);
}

std::optional<IPv4> IPv4::parse(std::string_view s) {
    std::array<uint8_t, 4> bytes;
    size_t start = 0;
    size_t dots = 0;

    for (int octet = 0; octet < 4; ++octet) {
        size_t end = s.find('.', start);
        if (end == std::string::npos) end = s.size();
        else ++dots;
        if (end == start) return std::nullopt;
        if (end - start > 3) return std::nullopt;

        int val = 0;
        for (size_t i = start; i < end; ++i) {
            if (!std::isdigit(static_cast<unsigned char>(s[i]))) return std::nullopt;
            val = val * 10 + (s[i] - '0');
            if (val > 255) return std::nullopt;
        }
        bytes[octet] = static_cast<uint8_t>(val);
        start = end + 1;
    }

    if (dots != 3) return std::nullopt;
    return IPv4{bytes};
}

std::string IPv4::to_string() const {
    return std::format("{}.{}.{}.{}", bytes_[0], bytes_[1], bytes_[2], bytes_[3]);
}

static std::optional<uint16_t> parse_hex_quartet(std::string_view s) {
    if (s.empty() || s.size() > 4) return std::nullopt;
    uint16_t val = 0;
    for (char c : s) {
        int h = hex_val(c);
        if (h < 0) return std::nullopt;
        val = static_cast<uint16_t>((val << 4) | h);
    }
    return val;
}

std::optional<IPv6> IPv6::parse(std::string_view s) {
    std::array<uint8_t, 16> bytes{};

    if (s == "::") return IPv6{bytes};

    if (auto dc = s.find("::"); dc != std::string_view::npos) {
        if (s.find("::", dc + 2) != std::string_view::npos) return std::nullopt;
    }

    uint16_t groups[8]{};
    size_t gi = 0;
    bool has_dcolon = false;
    size_t dcolon_idx = 0;

    size_t start = 0;
    while (start < s.size()) {
        if (start + 1 < s.size() && s[start] == ':' && s[start + 1] == ':') {
            if (has_dcolon) return std::nullopt;
            has_dcolon = true;
            dcolon_idx = gi;
            start += 2;
            continue;
        }
        size_t end = s.find(':', start);
        if (end == std::string_view::npos) end = s.size();
        if (gi >= 8) return std::nullopt;

        auto val = parse_hex_quartet(s.substr(start, end - start));
        if (!val) return std::nullopt;
        groups[gi++] = *val;

        if (end < s.size() && end + 1 < s.size() && s[end] == ':' && s[end + 1] == ':') {
            if (has_dcolon) return std::nullopt;
            has_dcolon = true;
            dcolon_idx = gi;
            start = end + 2;
        } else {
            start = end + 1;
        }
        if (end == s.size()) break;
    }

    if (!has_dcolon && gi != 8) return std::nullopt;
    if (has_dcolon && gi > 8) return std::nullopt;

    size_t src = 0;
    for (size_t i = 0; i < 8; ++i) {
        uint16_t v;
        if (has_dcolon && i >= dcolon_idx && i < dcolon_idx + (8 - gi)) {
            v = 0;
        } else {
            v = groups[src++];
        }
        bytes[i * 2] = static_cast<uint8_t>(v >> 8);
        bytes[i * 2 + 1] = static_cast<uint8_t>(v & 0xFF);
    }

    return IPv6{bytes};
}

std::string IPv6::to_string() const {
    return std::format("{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
                       (bytes_[0] << 8) | bytes_[1],
                       (bytes_[2] << 8) | bytes_[3],
                       (bytes_[4] << 8) | bytes_[5],
                       (bytes_[6] << 8) | bytes_[7],
                       (bytes_[8] << 8) | bytes_[9],
                       (bytes_[10] << 8) | bytes_[11],
                       (bytes_[12] << 8) | bytes_[13],
                       (bytes_[14] << 8) | bytes_[15]);
}

} // namespace packet
