/*
 * Gatekeeper - DDoS protection system.
 * Copyright (C) 2016 Digirati LTDA.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _GATEKEEPER_ABSFLOW_H_
#define _GATEKEEPER_ABSFLOW_H_

#include <stdbool.h>
#include <stdint.h>

#include <rte_byteorder.h>

#include "gatekeeper_net.h"

/*
 * Add a flow for the Ethernet type @ether_type.
 *
 * If the flow is implemented in hardware, the packets are delivered to
 * queue @queue_id. Otherwise, the packets are delivered to @submit.
 *
 * If @use_hw_if_available is true, it tries to offload the flow to
 * the hardware.
 */
int absflow_add_ethertype_filter(struct gatekeeper_if *iface,
	uint16_t ether_type, uint16_t queue_id, absflow_submit_func submit,
	bool use_hw_if_available);

/*
 * Add a filter for IPv4 packets based on the destination IP address,
 * source and destination ports, and protocol.
 *
 * The destination IP address as well as all ports and masks
 * should all be big endian when passed to this function. Although
 * ntuple filters use big endian values, ACLs use host ordering,
 * so this function converts these values to host ordering when
 * the ACL is used.
 *
 * @dst_ip_be: destination IP address to match against
 * @src_port_be: L4 source port to match against
 * @src_port_mask_be: mask for @src_port_be; set to 0xFFFF to match
 *     against @src_port_be, or set to 0 to not match against @src_port_be
 * @dst_port_be: L4 destination port to match against
 * @dst_port_mask_be: mask for @dst_port_be; set to 0xFFFF to match
 *     against @dst_port_be, or set to 0 to not match against @dst_port_be
 * @proto: next header protocol to match against
 *
 * Filters can be installed using whatever methods are available,
 * including ntuple filters (if supported by hardware) or ACLs
 * (as a software backup). Depending on the method used, the block
 * that uses the filter may need to query the NIC or a mailbox, etc.
 * Therefore, this function inserts the RX method needed into
 * @rx_method by logical OR'ing it into the existing value.
 *
 * @queue_id: the RX queue ID to which matching packets are
 *     steered (if ntuple filters are supported)
 * @cb_f: the function that is invoked on matching packets
 *     (if the ACL is being used)
 * @ext_cb_f: the function that is invoked on potential
 *     matching packets that checks for variable-length/extension
 *     headers (if the ACL is being used)
 *
 * TODO return flow id, so we can get uint8_t *rx_method later.
 */
int absflow_add_ipv4_filter(struct gatekeeper_if *iface, rte_be32_t dst_ip_be,
	rte_be16_t src_port_be, rte_be16_t src_port_mask_be,
	rte_be16_t dst_port_be, rte_be16_t dst_port_mask_be,
	uint8_t proto, uint16_t queue_id,
	absflow_submit_func submit, bool use_hw_if_available);

/*
 * Add a filter for IPv6 packets based on the destination IP address,
 * source and destination ports, and protocol.
 *
 * The destination IP address as well as all ports and masks
 * should all be big endian when passed to this function. Although
 * ntuple filters use big endian values, ACLs use host ordering,
 * so this function converts these values to host ordering when
 * the ACL is used.
 *
 * @dst_ip_be_ptr32: pointer to destination IP address to match against
 * @src_port_be: L4 source port to match against
 * @src_port_mask_be: mask for @src_port_be; set to 0xFFFF to match
 *     against @src_port_be, or set to 0 to not match against @src_port_be
 * @dst_port_be: L4 destination port to match against
 * @dst_port_mask_be: mask for @dst_port_be; set to 0xFFFF to match
 *     against @dst_port_be, or set to 0 to not match against @dst_port_be
 * @proto: next header protocol to match against
 *
 * Filters can be installed using whatever methods are available,
 * including ntuple filters (if supported by hardware) or ACLs
 * (as a software backup). Depending on the method used, the block
 * that uses the filter may need to query the NIC or a mailbox, etc.
 * Therefore, this function inserts the RX method needed into
 * @rx_method by logical OR'ing it into the existing value.
 *
 * @queue_id: the RX queue ID to which matching packets are
 *     steered (if ntuple filters are supported)
 * @cb_f: the function that is invoked on matching packets
 *     (if the ACL is being used)
 * @ext_cb_f: the function that is invoked on potential
 *     matching packets that checks for variable-length/extension
 *     headers (if the ACL is being used)
 *
 * TODO return flow id, so we can get uint8_t *rx_method later.
 */
int absflow_add_ipv6_filter(struct gatekeeper_if *iface,
	const uint8_t *dst_ip_be,
	rte_be16_t src_port_be, rte_be16_t src_port_mask_be,
	rte_be16_t dst_port_be, rte_be16_t dst_port_mask_be,
	uint8_t proto, uint16_t queue_id, absflow_submit_func submit,
	bool use_hw_if_available);

int absflow_rx_method(const struct gatekeeper_if *iface,
	const unsigned int *flow_ids, unsigned int ids_count,
	uint8_t *prx_method);

int absflow_add_submit(struct absflow_execution *exec, unsigned int flow_id,
	absflow_submit_func submit);

int absflow_deploy_flows(struct gatekeeper_if *iface);

void absflow_direct_infos(struct absflow_packet *infos, uint16_t count,
	struct gatekeeper_if *iface, const struct absflow_execution *exec,
	void *director_arg);

void absflow_direct_packets(struct rte_mbuf **pkts, uint16_t pkt_count,
	struct gatekeeper_if *iface, const struct absflow_execution *exec,
	void *director_arg);

static inline void absflow_direct_rss_packets(struct rte_mbuf **pkts,
	uint16_t pkt_count, struct gatekeeper_if *iface, void *director_arg)
{
	absflow_direct_packets(pkts, pkt_count, iface,
		&iface->absflow_dir.dir_exec, director_arg);
}

void absflow_free_exec(struct absflow_execution *exec);

/*
 * The following definitions are mainly meant for internal use of
 * the Abstract Flow Library.
 */

#define FLOW_HUMAN_STR_SIZE	(1024)

void flow_human_str(char *buf, size_t size, const struct absflow_desc *desc);

enum ft_source {FTS_L2_HEADER,
	FTS_L3_HEADER, FTS_L3_PROTO,
	FTS_L4_HEADER, FTS_L4_PROTO, FTS_L4_LEN, FTS_L4_FRAGMENTED,
};

struct flow_tree_node {
	enum ft_source source;

	/* Parameters for FTS_*_HEADER *only*. */
	uint16_t hdr_offset;
	uint16_t hdr_length;

	uint64_t mask;
	uint64_t value;

	/* If @has_flow_id is true, the flow ID is in @flow_id. */
	bool     has_flow_id;
	uint32_t flow_id;

	struct flow_tree_node *and_branch;
	struct flow_tree_node *or_branch;
};

int absflow_enable_exec(struct absflow_execution *exec,
	const struct flow_tree_node *root);

unsigned int absflow_classify_packet(const struct absflow_execution *exec,
	const struct absflow_packet *info);

#endif /* _GATEKEEPER_ABSFLOW_H_ */
