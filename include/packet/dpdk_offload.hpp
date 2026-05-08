#pragma once

#include "packet/packet_serializer.hpp"

struct rte_mbuf;

namespace packet {

void apply_dpdk_offload_request(rte_mbuf& mbuf, const PacketOffloadRequest& request);

} // namespace packet
