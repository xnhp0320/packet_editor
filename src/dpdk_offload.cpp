#include "packet/dpdk_offload.hpp"

#include <rte_mbuf.h>

namespace packet {

void apply_dpdk_offload_request(rte_mbuf& mbuf, const PacketOffloadRequest& request) {
    const auto needs_l3 = request.ipv4_checksum || request.tcp_checksum || request.udp_checksum;
    if (!needs_l3) {
        return;
    }

    mbuf.l2_len = request.l2_len;
    mbuf.l3_len = request.l3_len;
    mbuf.l4_len = request.l4_len;

    if (request.layer3 == OffloadLayer3::IPv4 || request.ipv4_checksum) {
        mbuf.ol_flags |= RTE_MBUF_F_TX_IPV4;
    } else if (request.layer3 == OffloadLayer3::IPv6) {
        mbuf.ol_flags |= RTE_MBUF_F_TX_IPV6;
    }

    if (request.ipv4_checksum) {
        mbuf.ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
    }

    if (request.tcp_checksum || request.udp_checksum) {
        mbuf.ol_flags &= ~RTE_MBUF_F_TX_L4_MASK;
        mbuf.ol_flags |= request.tcp_checksum ? RTE_MBUF_F_TX_TCP_CKSUM
                                              : RTE_MBUF_F_TX_UDP_CKSUM;
    }
}

} // namespace packet
