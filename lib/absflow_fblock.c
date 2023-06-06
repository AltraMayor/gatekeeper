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

#include <rte_ip_frag.h>

#include "memblock.h"
#include "gatekeeper_main.h"
#include "gatekeeper_l2.h"
#include "gatekeeper_varip.h"
#include "gatekeeper_absflow.h"

static int
register_submit(struct absflow_execution *exec, absflow_submit_func submit)
{
	unsigned int i, count = exec->submits_count;

	/*
	 * Combining submit functions is important to group more packets for
	 * each call of @submit.
	 */
	for (i = 0; i < count; i++) {
		if (exec->submits[i] == submit)
			return i;
	}

	if (unlikely(count >= GATEKEEPER_ABSFLOW_MAX)) {
		G_LOG(ERR, "%s(): cannot install more submit functions\n",
			__func__);
		return -ENOENT;
	}

	exec->submits[count] = submit;
	exec->submits_count++;
	return count;
}

#define ALLOC_PARAM(name, n)						\
	name = memblock_calloc(desc->memblock, (n), sizeof(*name));	\
	if (unlikely(name == NULL)) {					\
		G_LOG(ERR, "%s(%s): cannot allocate parameter\n",	\
			__func__, #name);				\
		return -ENOENT;						\
	}								\
	do { } while (0)

static int
get_flow_id(struct gatekeeper_if *iface)
{
	uint32_t flow_id = iface->absflow_dir.flow_descs_count;
	if (flow_id >= GATEKEEPER_ABSFLOW_MAX) {
		G_LOG(ERR, "%s(%s): cannot install more flows\n",
			__func__, iface->name);
		return -ENOENT;
	}
	iface->absflow_dir.flow_descs_count++;
	return flow_id;
}

static int
put_flow_id(struct gatekeeper_if *iface, uint32_t flow_id)
{
	if (unlikely(iface->absflow_dir.flow_descs_count != flow_id + 1)) {
		/* Only the *last* flow ID can be released. */
		G_LOG(ERR, "%s(%s): cannot release flow ID %u\n",
			__func__, iface->name, flow_id);
		return -ENOTSUP;
	}
	iface->absflow_dir.flow_descs_count--;
	return 0;
}

static int
iface_to_desc(struct gatekeeper_if *iface, uint32_t flow_id,
	struct absflow_desc **pdesc)
{
	if (unlikely(flow_id >= iface->absflow_dir.flow_descs_count)) {
		G_LOG(ERR, "%s(%s): invalid flow ID %u\n",
			__func__, iface->name, flow_id);
		*pdesc = NULL;
		return -EINVAL;
	}
	*pdesc = &iface->absflow_dir.flow_descs[flow_id];
	return 0;
}

static void
put_desc(struct absflow_desc *desc)
{
	memblock_free_block(desc->memblock);
	memset(desc, 0, sizeof(*desc));
}

/* @desc->memblock must be already allocated. */
static int
init_desc_attr_action(struct absflow_desc *desc, uint16_t queue_id,
	bool use_hw_if_available)
{
	struct rte_flow_attr *attr;
	struct rte_flow_action_queue *queue;
	struct rte_flow_action *action;

	if (!use_hw_if_available) {
		desc->attr = NULL;
		desc->action = NULL;
		return 0;
	}

	ALLOC_PARAM(attr, 1);
	attr->ingress = 1;
	desc->attr = attr;

	ALLOC_PARAM(queue, 1);
	queue->index = queue_id;
	ALLOC_PARAM(action, 2);
	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = queue;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;
	desc->action = action;
	return 0;
}

static int
absflow_add_flow(struct gatekeeper_if *iface, uint32_t flow_id,
	uint16_t queue_id, absflow_submit_func submit, bool use_hw_if_available)
{
	int ret;
	unsigned int submit_idx;
	struct absflow_execution *exec;
	struct absflow_desc *desc;

	if (unlikely(!iface->rss)) {
		/*
		 * If RSS is not supported, then flow packets could be
		 * assigned to RX queues that are serviced by non-RSS blocks
		 * such as the LLS.
		 */
		G_LOG(NOTICE, "%s(%s): abstract filters require RSS, which is not supported\n",
			__func__, iface->name);
		return -EINVAL;
	}

	exec = &iface->absflow_dir.dir_exec;
	ret = register_submit(exec, submit);
	if (unlikely(ret < 0))
		return ret;
	submit_idx = ret;

	ret = iface_to_desc(iface, flow_id, &desc);
	if (unlikely(ret < 0)) {
		/*
		 * There's no need to release @submit_idx because
		 * register_submit() deduplicates the indexes of @submit.
		 */
		return ret;
	}
	desc->hw_supported = false;
	/* This field will be properly set later. */
	desc->hw_offloaded = false;

	ret = init_desc_attr_action(desc, queue_id, use_hw_if_available);
	if (unlikely(ret < 0))
		return ret;

	if (use_hw_if_available) {
		struct rte_flow_error error;
		ret = rte_flow_validate(iface->id, desc->attr, desc->pattern,
			desc->action, &error);
		if (ret < 0) {
			char flow_str[FLOW_HUMAN_STR_SIZE];
			flow_human_str(flow_str, sizeof(flow_str), desc);
			G_LOG(NOTICE, "%s(%s): cannot validate flow %s (errno=%i: %s), rte_flow_error_type=%i: %s\n",
				__func__, iface->name, flow_str,
				-ret, rte_strerror(-ret),
				error.type, error.message);
		} else
			desc->hw_supported = true;
	}

	exec->flow_id_to_submit[flow_id] = submit_idx;
	return flow_id;
}

static int
init_desc_ethertype(struct absflow_desc *desc, uint16_t ether_type)
{
	/* Flow definition. */
	struct rte_flow_item_eth *eth_spec;
	struct rte_flow_item_eth *eth_mask;
	struct rte_flow_item *pattern;

	desc->memblock = memblock_alloc_block(1024, SOCKET_ID_ANY);
	if (unlikely(desc->memblock == NULL))
		return -ENOMEM;

	/*
	 * Tecnically, the DPDK rte_flow API allows filters to be specified
	 * on any field in an Ethernet header, but in practice,
	 * drivers implement the RTE_FLOW_ITEM_TYPE_ETH using the EtherType
	 * filters available in hardware. Typically, EtherType filters only
	 * support destination MAC addresses and the EtherType field.
	 * We choose to only allow the EtherType field to be specified
	 * since the destination MAC address may be extraneous anyway (#74).
	 */
	ALLOC_PARAM(eth_spec, 1);
	eth_spec->type = rte_cpu_to_be_16(ether_type);
	ALLOC_PARAM(eth_mask, 1);
	eth_mask->type = 0xFFFF;
	ALLOC_PARAM(pattern, 2);
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = eth_spec;
	pattern[0].mask = eth_mask;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	desc->pattern = pattern;
	return 0;
}

int
absflow_add_ethertype_filter(struct gatekeeper_if *iface, uint16_t ether_type,
	uint16_t queue_id, absflow_submit_func submit, bool use_hw_if_available)
{
	uint32_t flow_id;
	struct absflow_desc *desc;

	int ret = get_flow_id(iface);
	if (unlikely(ret < 0))
		goto out;
	flow_id = ret;

	ret = iface_to_desc(iface, flow_id, &desc);
	if (unlikely(ret < 0))
		goto flow_id;

	ret = init_desc_ethertype(desc, ether_type);
	if (unlikely(ret < 0))
		goto desc;

	ret = absflow_add_flow(iface, flow_id, queue_id, submit,
		use_hw_if_available);
	if (unlikely(ret < 0))
		goto desc;

	return flow_id;

desc:
	put_desc(desc);
flow_id:
	put_flow_id(iface, flow_id);
out:
	return ret;
}

/* @desc->memblock must be already allocated. */
static int
init_desc_ip_filter(struct absflow_desc *desc, enum rte_flow_item_type ip_type,
	const void *ip_spec, const void *ip_mask,
	rte_be16_t src_port_be, rte_be16_t src_port_mask_be,
	rte_be16_t dst_port_be, rte_be16_t dst_port_mask_be, uint16_t proto)
{
	struct rte_flow_item_eth *eth_spec;
	struct rte_flow_item_eth *eth_mask;
	struct rte_flow_item *pattern;
	uint8_t pattern_dim;

	bool has_port = (proto == IPPROTO_TCP) || (proto == IPPROTO_UDP);
	if (unlikely(!has_port &&
			(src_port_be != 0 || src_port_mask_be != 0 ||
			 dst_port_be != 0 || dst_port_mask_be != 0))) {
		G_LOG(ERR, "%s(): fields src_port_be, src_port_mask_be, dst_port_be, dst_port_mask_be must be zero when protocol has no port\n",
			__func__);
		return -EINVAL;
	}

	/* Ethernet */
	ALLOC_PARAM(eth_spec, 1);
	switch (ip_type) {
	case RTE_FLOW_ITEM_TYPE_IPV4:
		eth_spec->type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		break;
	case RTE_FLOW_ITEM_TYPE_IPV6:
		eth_spec->type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
		break;
	default:
		return -EINVAL;
	}
	ALLOC_PARAM(eth_mask, 1);
	eth_mask->type = 0xFFFF;

	/* Pattern */
	pattern_dim = has_port ? 4 : 3;
	ALLOC_PARAM(pattern, pattern_dim);
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = eth_spec;
	pattern[0].mask = eth_mask;
	pattern[1].type = ip_type;
	pattern[1].spec = ip_spec;
	pattern[1].mask = ip_mask;
	pattern[pattern_dim - 1].type = RTE_FLOW_ITEM_TYPE_END;

	switch (proto) {
	case IPPROTO_TCP: {
		struct rte_flow_item_tcp *tcp_spec;
		struct rte_flow_item_tcp *tcp_mask;
		ALLOC_PARAM(tcp_spec, 1);
		tcp_spec->hdr.src_port = src_port_be;
		tcp_spec->hdr.dst_port = dst_port_be;
		ALLOC_PARAM(tcp_mask, 1);
		tcp_mask->hdr.src_port = src_port_mask_be;
		tcp_mask->hdr.dst_port = dst_port_mask_be;
		pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
		pattern[2].spec = tcp_spec;
		pattern[2].mask = tcp_mask;
		break;
	}
	case IPPROTO_UDP: {
		struct rte_flow_item_udp *udp_spec;
		struct rte_flow_item_udp *udp_mask;
		ALLOC_PARAM(udp_spec, 1);
		udp_spec->hdr.src_port = src_port_be;
		udp_spec->hdr.dst_port = dst_port_be;
		ALLOC_PARAM(udp_mask, 1);
		udp_mask->hdr.src_port = src_port_mask_be;
		udp_mask->hdr.dst_port = dst_port_mask_be;
		pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
		pattern[2].spec = udp_spec;
		pattern[2].mask = udp_mask;
		break;
	}
	default:
		if (likely(!has_port))
			break;
		G_LOG(CRIT, "%s(): bug: unexpected protocol %hu\n",
			__func__, proto);
		return -EFAULT;
	}

	desc->pattern = pattern;
	return 0;
}

static int
init_desc_ipv4_filter(struct absflow_desc *desc, rte_be32_t dst_ip_be,
	rte_be16_t src_port_be, rte_be16_t src_port_mask_be,
	rte_be16_t dst_port_be, rte_be16_t dst_port_mask_be, uint16_t proto)
{
	struct rte_flow_item_ipv4 *ipv4_spec;
	struct rte_flow_item_ipv4 *ipv4_mask;

	desc->memblock = memblock_alloc_block(1024, SOCKET_ID_ANY);
	if (unlikely(desc->memblock == NULL))
		return -ENOMEM;

	ALLOC_PARAM(ipv4_spec, 1);
	ipv4_spec->hdr.dst_addr = dst_ip_be;
	ALLOC_PARAM(ipv4_mask, 1);
	ipv4_mask->hdr.dst_addr = 0xFFFFFFFF;

	if (proto < 0x100) {
		ipv4_spec->hdr.next_proto_id = proto;
		ipv4_mask->hdr.next_proto_id = 0xFF;
	}

	return init_desc_ip_filter(desc,
		RTE_FLOW_ITEM_TYPE_IPV4, ipv4_spec, ipv4_mask,
		src_port_be, src_port_mask_be, dst_port_be, dst_port_mask_be,
		proto);
}

int
absflow_add_ipv4_filter(struct gatekeeper_if *iface, rte_be32_t dst_ip_be,
	rte_be16_t src_port_be, rte_be16_t src_port_mask_be,
	rte_be16_t dst_port_be, rte_be16_t dst_port_mask_be,
	uint16_t proto, uint16_t queue_id, absflow_submit_func submit,
	bool use_hw_if_available)
{
	uint32_t flow_id;
	struct absflow_desc *desc;

	int ret = get_flow_id(iface);
	if (unlikely(ret < 0))
		goto out;
	flow_id = ret;

	ret = iface_to_desc(iface, flow_id, &desc);
	if (unlikely(ret < 0))
		goto flow_id;

	ret = init_desc_ipv4_filter(desc, dst_ip_be, src_port_be,
		src_port_mask_be, dst_port_be, dst_port_mask_be, proto);
	if (unlikely(ret < 0))
		goto desc;

	ret = absflow_add_flow(iface, flow_id, queue_id, submit,
		use_hw_if_available);
	if (unlikely(ret < 0))
		goto desc;

	return flow_id;

desc:
	put_desc(desc);
flow_id:
	put_flow_id(iface, flow_id);
out:
	return ret;
}

static int
init_desc_ipv6_filter(struct absflow_desc *desc, const uint8_t *dst_ip_be,
	rte_be16_t src_port_be, rte_be16_t src_port_mask_be,
	rte_be16_t dst_port_be, rte_be16_t dst_port_mask_be, uint16_t proto)
{
	struct rte_flow_item_ipv6 *ipv6_spec;
	struct rte_flow_item_ipv6 *ipv6_mask;

	desc->memblock = memblock_alloc_block(1024, SOCKET_ID_ANY);
	if (unlikely(desc->memblock == NULL))
		return -ENOMEM;

	ALLOC_PARAM(ipv6_spec, 1);
	RTE_BUILD_BUG_ON(sizeof(ipv6_spec->hdr.dst_addr) != 16);
	rte_mov16(ipv6_spec->hdr.dst_addr, dst_ip_be);
	ALLOC_PARAM(ipv6_mask, 1);
	memset(ipv6_mask->hdr.dst_addr, 0xFF, sizeof(ipv6_mask->hdr.dst_addr));

	if (proto < 0x100) {
		ipv6_spec->hdr.proto = proto;
		ipv6_mask->hdr.proto = 0xFF;
	}

	return init_desc_ip_filter(desc,
		RTE_FLOW_ITEM_TYPE_IPV6, ipv6_spec, ipv6_mask,
		src_port_be, src_port_mask_be, dst_port_be, dst_port_mask_be,
		proto);
}

int
absflow_add_ipv6_filter(struct gatekeeper_if *iface, const uint8_t *dst_ip_be,
	rte_be16_t src_port_be, rte_be16_t src_port_mask_be,
	rte_be16_t dst_port_be, rte_be16_t dst_port_mask_be,
	uint16_t proto, uint16_t queue_id, absflow_submit_func submit,
	bool use_hw_if_available)
{
	uint32_t flow_id;
	struct absflow_desc *desc;

	int ret = get_flow_id(iface);
	if (unlikely(ret < 0))
		goto out;
	flow_id = ret;

	ret = iface_to_desc(iface, flow_id, &desc);
	if (unlikely(ret < 0))
		goto flow_id;

	ret = init_desc_ipv6_filter(desc, dst_ip_be, src_port_be,
		src_port_mask_be, dst_port_be, dst_port_mask_be, proto);
	if (unlikely(ret < 0))
		goto desc;

	ret = absflow_add_flow(iface, flow_id, queue_id, submit,
		use_hw_if_available);
	if (unlikely(ret < 0))
		goto desc;

	return flow_id;

desc:
	put_desc(desc);
flow_id:
	put_flow_id(iface, flow_id);
out:
	return ret;
}

/* TODO Shouldn't we drop this function? */
int
absflow_rx_method(const struct gatekeeper_if *iface,
	const unsigned int *flow_ids, unsigned int ids_count,
	uint8_t *prx_method)
{
	unsigned int i;
	uint8_t rx_method = 0;

	if (unlikely(!iface->absflow_dir.dir_working)) {
		G_LOG(ERR, "%s(): abstract flow has not been built\n",
			__func__);
		return -EBUSY;
	}

	for (i = 0; i < ids_count; i++) {
		unsigned int flow_id = flow_ids[i];
		if (unlikely(flow_id >= GATEKEEPER_ABSFLOW_MAX)) {
			G_LOG(ERR, "%s(): invalid flow_id=%u\n",
				__func__, flow_id);
			return -EINVAL;
		}
		rx_method |= iface->absflow_dir.flow_descs[flow_id].hw_offloaded
			? RX_METHOD_NIC : RX_METHOD_MB;
	}
	*prx_method = rx_method;
	return 0;
}

void
absflow_init_exec(struct absflow_execution *exec)
{
	unsigned int i;

	/*
	 * Make sure that GATEKEEPER_ABSFLOW_INVALID_FLOWID is actually
	 * an invalid flow ID.
	 *
	 * Add "=" to the inequality to guarantee that both constants are
	 * distinct.
	 */
	RTE_BUILD_BUG_ON(GATEKEEPER_ABSFLOW_INVALID_FLOWID <=
		GATEKEEPER_ABSFLOW_MAX);

	exec->submits_count = 0;
	memset(exec->submits, 0, sizeof(exec->submits));

	for (i = 0; i < RTE_DIM(exec->flow_id_to_submit); i++)
		exec->flow_id_to_submit[i] = RTE_DIM(exec->submits);

	exec->f_class = NULL;
	exec->f_class_jit = NULL;
}

int
absflow_add_submit(struct absflow_execution *exec, unsigned int flow_id,
	absflow_submit_func submit)
{
	int ret;

	if (unlikely(flow_id) >= GATEKEEPER_ABSFLOW_MAX)
		return -EINVAL;

	ret = register_submit(exec, submit);
	if (unlikely(ret < 0))
		return ret;
	exec->flow_id_to_submit[flow_id] = ret;

	return 0;
}

static int
extract_packet_info(struct rte_mbuf *pkt, struct absflow_packet *info)
{
	uint16_t pkt_len = rte_pktmbuf_data_len(pkt);
	struct rte_ether_hdr *eth_hdr =
		rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);

	info->pkt = pkt;
	info->l3_proto = rte_be_to_cpu_16(
		pkt_in_skip_l2(pkt, eth_hdr, &info->l3_hdr));
	info->l2_len = pkt_in_l2_hdr_len(pkt);

	switch (info->l3_proto) {
	case RTE_ETHER_TYPE_IPV4: {
		struct rte_ipv4_hdr *ipv4_hdr;

		if (unlikely(pkt_len < info->l2_len + sizeof(*ipv4_hdr))) {
			G_LOG(DEBUG, "%s(): packet is too short to be IPv4 (%i)\n",
				__func__, pkt_len);
			return -EINVAL;
		}

		ipv4_hdr = info->l3_hdr;
		info->l3_len = ipv4_hdr_len(ipv4_hdr);
		info->l4_proto = ipv4_hdr->next_proto_id;
		info->l4_fragmented = rte_ipv4_frag_pkt_is_fragmented(ipv4_hdr);
		break;
	}

	case RTE_ETHER_TYPE_IPV6: {
		struct rte_ipv6_hdr *ipv6_hdr;
		int l3_len;
		uint8_t l4_proto;

		if (unlikely(pkt_len < info->l2_len + sizeof(*ipv6_hdr))) {
			G_LOG(DEBUG, "%s(): packet is too short to be IPv6 (%i)\n",
				__func__, pkt_len);
			return -EINVAL;
		}

		ipv6_hdr = info->l3_hdr;
		l3_len = ipv6_skip_exthdr(ipv6_hdr, pkt_len - info->l2_len,
			&l4_proto);
		if (unlikely(l3_len < 0)) {
			G_LOG(DEBUG, "%s(): failed to parse IPv6 extension headers (errno=%i): %s\n",
				__func__, -l3_len, strerror(-l3_len));
			return l3_len;
		}
		info->l3_len = l3_len;
		info->l4_proto = l4_proto;
		info->l4_fragmented = rte_ipv6_frag_get_ipv6_fragment_header(
			ipv6_hdr) != NULL;
		break;
	}

	case RTE_ETHER_TYPE_ARP:
		info->l3_len = sizeof(struct rte_arp_hdr);
		if (unlikely(pkt_len < info->l2_len + info->l3_len)) {
			G_LOG(DEBUG, "%s(): packet is too short to be ARP (%i)\n",
				__func__, pkt_len);
			return -EINVAL;
		}
		info->l4_proto = -1; /* Invalid protocol. */
		info->l4_fragmented = false;
		break;

	default:
		log_unknown_l2(__func__, info->l3_proto);
		info->l3_len = pkt_len - info->l2_len;
		info->l4_len = 0;
		info->l4_proto = -1; /* Invalid protocol. */
		info->l4_fragmented = false;
		info->l4_hdr = RTE_PTR_ADD(info->l3_hdr, info->l3_len);
		return -ENOTSUP;
	}

	info->l4_len = pkt_len - info->l2_len - info->l3_len;
	info->l4_hdr = RTE_PTR_ADD(info->l3_hdr, info->l3_len);
	return 0;
}

void
absflow_free_packets(struct absflow_packet **infos, uint16_t n)
{
	struct rte_mbuf *pkts[n];
	unsigned int i;

	for (i = 0; i < n; i++)
		pkts[i] = infos[i]->pkt;
	rte_pktmbuf_free_bulk(pkts, n);
}

void
absflow_direct_infos(struct absflow_packet *infos, uint16_t count,
	struct gatekeeper_if *iface, const struct absflow_execution *exec,
	void *director_arg)
{
	/* The extra row is for unclassified packets. */
	struct absflow_packet *infos_matrix[exec->submits_count + 1][count];
	typeof(count) infos_per_row[exec->submits_count + 1];
	typeof(count) n;
	unsigned int i, flow_descs_count;

	RTE_BUILD_BUG_ON(GATEKEEPER_ABSFLOW_INVALID_FLOWID <
		GATEKEEPER_ABSFLOW_MAX);
	memset(infos_per_row, 0, sizeof(infos_per_row));
	flow_descs_count = iface->absflow_dir.flow_descs_count;
	for (i = 0; i < count; i++) {
		struct absflow_packet *info = &infos[i];
		unsigned int submit_id;

		if (likely(info->flow_id < flow_descs_count)) {
			submit_id = exec->flow_id_to_submit[info->flow_id];
			if (unlikely(submit_id >= exec->submits_count)) {
				G_LOG(CRIT, "%s(): bug: submit_id=%u >= submits_count=%u; failsafe: marking packet as unclassified\n",
					__func__, submit_id,
					exec->submits_count);
				/* Unclassified. */
				submit_id = exec->submits_count;
			}
		} else {
			if (unlikely(info->flow_id !=
					GATEKEEPER_ABSFLOW_INVALID_FLOWID)) {
				G_LOG(CRIT, "%s(): bug: flow_id=%u\n",
					__func__, info->flow_id);
			}
			/* Unclassified. */
			submit_id = exec->submits_count;
		}
		infos_matrix[submit_id][infos_per_row[submit_id]++] = info;
	}

	for (i = 0; i < exec->submits_count; i++) {
		n = infos_per_row[i];
		if (n == 0)
			continue;
		exec->submits[i](infos_matrix[i], n, iface, director_arg);
	}

	n = infos_per_row[exec->submits_count];
	if (unlikely(n > 0)) {
		/* Free unclassified packets. */
		absflow_free_packets(infos_matrix[exec->submits_count], n);
	}
}

/* TODO Add prefetches. */
void
absflow_direct_packets(struct rte_mbuf **pkts, uint16_t pkt_count,
	struct gatekeeper_if *iface, const struct absflow_execution *exec,
	void *director_arg)
{
	struct absflow_packet infos[pkt_count];
	unsigned int i;

	for (i = 0; i < pkt_count; i++) {
		struct absflow_packet *info = &infos[i];
		int ret = extract_packet_info(pkts[i], info);
		info->flow_id = likely(ret >= 0)
			? absflow_classify_packet(exec, info)
			/* Mark the packet as unclassified. */
			: GATEKEEPER_ABSFLOW_INVALID_FLOWID;
	}

	absflow_direct_infos(infos, pkt_count, iface, exec,
		director_arg);
}
