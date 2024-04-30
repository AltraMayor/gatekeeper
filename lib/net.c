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

#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/random.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <net/if.h>

#include <rte_mbuf.h>
#include <rte_thash.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_eth_bond.h>
#include <rte_malloc.h>
#include <rte_pmd_i40e.h>

#include "gatekeeper_acl.h"
#include "gatekeeper_main.h"
#include "gatekeeper_net.h"
#include "gatekeeper_config.h"
#include "gatekeeper_launch.h"

static struct net_config config;

/*
 * Add a filter that steers packets to queues based on their EtherType.
 *
 * Tecnically, the DPDK rte_flow API allows filters to be specified
 * on any field in an Ethernet header, but in practice, drivers implement
 * the RTE_FLOW_ITEM_TYPE_ETH using the EtherType filters available
 * in hardware. Typically, EtherType filters only support destination
 * MAC addresses and the EtherType field. We choose to only allow
 * the EtherType field to be specified, since the destination MAC
 * address may be extraneous anyway (#74).
 *
 * @ether_type should be passed in host ordering, but is converted
 * to big endian ordering before being added as a filter, as
 * required by the rte_flow API. Individual device drivers can then
 * convert it to whatever endianness is needed.
 */
int
ethertype_flow_add(struct gatekeeper_if *iface, uint16_t ether_type,
	uint16_t queue_id)
{
	struct rte_flow_attr attr = { .ingress = 1 };
	struct rte_flow_action_queue queue = { .index = queue_id };
	struct rte_flow_action action[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue,
	       	},
		{
			.type = RTE_FLOW_ACTION_TYPE_END,
		}
	};
	struct rte_flow_item_eth eth_spec = {
		.type = rte_cpu_to_be_16(ether_type),
	};
	struct rte_flow_item_eth eth_mask = {
		.type = 0xFFFF,
	};
	struct rte_flow_item pattern[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &eth_spec,
			.mask = &eth_mask,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};
	struct rte_flow_error error;
	struct rte_flow *flow;
	int ret;

	if (!iface->rss) {
		/*
		 * If RSS is not supported, then data plane packets
		 * could be assigned to RX queues that are serviced
		 * by non-data plane blocks (e.g., LLS).
		 */
		G_LOG(NOTICE, "%s(%s): cannot use EtherType filters when RSS is not supported\n",
			__func__, iface->name);
		return -1;
	}

	ret = rte_flow_validate(iface->id, &attr, pattern, action, &error);
	if (ret < 0) {
		/*
		 * A negative errno value was returned
		 * (and also put in rte_errno).
		 */
		G_LOG(NOTICE, "%s(%s): cannot validate EtherType=0x%x flow, errno=%i (%s), rte_flow_error_type=%i: %s\n",
			__func__, iface->name, ether_type,
			-ret, rte_strerror(-ret),
			error.type, error.message);
		return -1;
	}

	flow = rte_flow_create(iface->id, &attr, pattern, action, &error);
	if (flow == NULL) {
		/* rte_errno is set to a positive errno value. */
		G_LOG(ERR, "%s(%s): cannot create EtherType=0x%x flow, errno=%i (%s), rte_flow_error_type=%i: %s\n",
			__func__, iface->name, ether_type,
			rte_errno, rte_strerror(rte_errno),
			error.type, error.message);
		return -1;
	}

	G_LOG(NOTICE, "%s(%s): EtherType=0x%x flow supported\n",
		__func__, iface->name, ether_type);
	return 0;
}

#define STR_NOIP "NO IP"
static int
ipv4_flow_add(struct gatekeeper_if *iface, rte_be32_t dst_ip_be,
	rte_be16_t src_port_be, rte_be16_t src_port_mask_be,
	rte_be16_t dst_port_be, rte_be16_t dst_port_mask_be,
	uint8_t proto, uint16_t queue_id)
{
	struct rte_flow_attr attr = { .ingress = 1, };
	struct rte_flow_action_queue queue = { .index = queue_id };
	struct rte_flow_action action[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue,
	       	},
		{
			.type = RTE_FLOW_ACTION_TYPE_END,
		}
	};
	struct rte_flow_item_eth eth_spec = {
		.type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4),
	};
	struct rte_flow_item_eth eth_mask = {
		.type = 0xFFFF,
	};
	struct rte_flow_item_ipv4 ip_spec = {
		.hdr = {
			.dst_addr = dst_ip_be,
			.next_proto_id = proto,
		}
	};
	struct rte_flow_item_ipv4 ip_mask = {
		.hdr = {
			.dst_addr = 0xFFFFFFFF,
			.next_proto_id = 0xFF,
		}
	};
	struct rte_flow_item pattern[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &eth_spec,
			.mask = &eth_mask,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &ip_spec,
			.mask = &ip_mask,
		},
		{ },
		{
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};
	struct rte_flow *flow;
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	struct rte_flow_error error;
	int ret;
	const char *str_proto = "NO PROTO";
	char str_dst_ip[INET_ADDRSTRLEN], str_flow[256];

	if (!iface->rss) {
		/*
		 * IPv4 flows can only be used if supported by the NIC
		 * (to steer matching packets) and if RSS is supported
		 * (to steer non-matching packets elsewhere).
		 */
		G_LOG(NOTICE, "%s(%s): cannot use IPv4 flows when RSS is not supported\n",
			__func__, iface->name);
		return -1;
	}

	if (proto == IPPROTO_TCP) {
		memset(&tcp_spec, 0, sizeof(tcp_spec));
		memset(&tcp_mask, 0, sizeof(tcp_mask));
		tcp_spec.hdr.src_port = src_port_be;
		tcp_mask.hdr.src_port = src_port_mask_be;
		tcp_spec.hdr.dst_port = dst_port_be;
		tcp_mask.hdr.dst_port = dst_port_mask_be;
		pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
		pattern[2].spec = &tcp_spec;
		pattern[2].mask = &tcp_mask;
		str_proto = "TCP";
	} else if (proto == IPPROTO_UDP) {
		memset(&udp_spec, 0, sizeof(udp_spec));
		memset(&udp_mask, 0, sizeof(udp_mask));
		udp_spec.hdr.src_port = src_port_be;
		udp_mask.hdr.src_port = src_port_mask_be;
		udp_spec.hdr.dst_port = dst_port_be;
		udp_mask.hdr.dst_port = dst_port_mask_be;
		pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
		pattern[2].spec = &udp_spec;
		pattern[2].mask = &udp_mask;
		str_proto = "UDP";
	} else {
		G_LOG(ERR, "%s(%s): unexpected L4 protocol %hu for IPv4 flow\n",
			__func__, iface->name, proto);
		return -1;
	}

	/* Get a human-readable description of the flow. */
	if (unlikely(inet_ntop(AF_INET, &dst_ip_be,
			str_dst_ip, sizeof(str_dst_ip)) == NULL)) {
		G_LOG(ERR, "%s(%s): inet_ntop() failed, errno=%i: %s\n",
			__func__, iface->name, errno, strerror(errno));
		RTE_BUILD_BUG_ON(sizeof(STR_NOIP) > sizeof(str_dst_ip));
		strcpy(str_dst_ip, STR_NOIP);
	}
	ret = snprintf(str_flow, sizeof(str_flow),
		"DstIP=%s %s SrcPort=%i/0x%x DstPort=%i/0x%x",
		str_dst_ip, str_proto,
		rte_be_to_cpu_16(src_port_be),
		rte_be_to_cpu_16(src_port_mask_be),
		rte_be_to_cpu_16(dst_port_be),
		rte_be_to_cpu_16(dst_port_mask_be));
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(str_flow));

	ret = rte_flow_validate(iface->id, &attr, pattern, action, &error);
	if (ret < 0) {
		/*
		 * A negative errno value was returned
		 * (and also put in rte_errno).
		 */
		G_LOG(NOTICE, "%s(%s, %s): cannot validate IPv4 flow, errno=%i (%s), rte_flow_error_type=%i: %s\n",
			__func__, iface->name, str_flow,
			-ret, rte_strerror(-ret),
			error.type, error.message);
		return -1;
	}

	flow = rte_flow_create(iface->id, &attr, pattern, action, &error);
	if (flow == NULL) {
		/* rte_errno is set to a positive errno value. */
		G_LOG(ERR, "%s(%s, %s): cannot create IPv4 flow, errno=%i (%s), rte_flow_error_type=%i: %s\n",
			__func__, iface->name, str_flow,
			rte_errno, rte_strerror(rte_errno),
			error.type, error.message);
		return -1;
	}

	G_LOG(NOTICE, "%s(%s, %s): IPv4 flow supported\n",
		__func__, iface->name, str_flow);
	return 0;
}

static void
ipv4_fill_acl_rule(struct ipv4_acl_rule *rule,
	rte_be32_t dst_ip_be,
	rte_be16_t src_port_be, rte_be16_t src_port_mask_be,
	rte_be16_t dst_port_be, rte_be16_t dst_port_mask_be,
	uint8_t proto)
{
	rule->data.category_mask = 0x1;
	rule->data.priority = 1;
	/* Userdata is filled in in register_ipv4_acl(). */

	rule->field[PROTO_FIELD_IPV4].value.u8 = proto;
	rule->field[PROTO_FIELD_IPV4].mask_range.u8 = 0xFF;

	rule->field[DST_FIELD_IPV4].value.u32 = rte_be_to_cpu_32(dst_ip_be);
	rule->field[DST_FIELD_IPV4].mask_range.u32 = 32;

	rule->field[SRCP_FIELD_IPV4].value.u16 = rte_be_to_cpu_16(src_port_be);
	rule->field[SRCP_FIELD_IPV4].mask_range.u16 =
		rte_be_to_cpu_16(src_port_mask_be);
	rule->field[DSTP_FIELD_IPV4].value.u16 = rte_be_to_cpu_16(dst_port_be);
	rule->field[DSTP_FIELD_IPV4].mask_range.u16 =
		rte_be_to_cpu_16(dst_port_mask_be);
}

int
ipv4_pkt_filter_add(struct gatekeeper_if *iface, rte_be32_t dst_ip_be,
	rte_be16_t src_port_be, rte_be16_t src_port_mask_be,
	rte_be16_t dst_port_be, rte_be16_t dst_port_mask_be,
	uint8_t proto, uint16_t queue_id,
	acl_cb_func cb_f, ext_cb_func ext_cb_f,
	uint8_t *rx_method)
{
	struct ipv4_acl_rule ipv4_rule = { };
	int ret;

	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		ret = ipv4_flow_add(iface, dst_ip_be,
			src_port_be, src_port_mask_be,
			dst_port_be, dst_port_mask_be,
			proto, queue_id);
		if (ret < 0) {
			G_LOG(NOTICE, "Cannot register IPv4 flow on the %s interface; falling back to software filters\n",
				iface->name);
			goto acl;
		}
		*rx_method |= RX_METHOD_NIC;
		return 0;
	}
acl:
	if (!ipv4_acl_enabled(iface)) {
		ret = init_ipv4_acls(iface);
		if (ret < 0)
			return ret;
	}

	ipv4_fill_acl_rule(&ipv4_rule, dst_ip_be,
		src_port_be, src_port_mask_be,
		dst_port_be, dst_port_mask_be,
		proto);
	ret = register_ipv4_acl(&ipv4_rule,
		cb_f, ext_cb_f, iface);
	if (ret < 0) {
		G_LOG(ERR, "Cannot register IPv4 ACL on the %s interface\n",
			iface->name);
		return ret;
	}
	*rx_method |= RX_METHOD_MB;

	return 0;
}

static void
ipv6_fill_acl_rule(struct ipv6_acl_rule *rule,
	const rte_be32_t *dst_ip_be_ptr32,
	rte_be16_t src_port_be, rte_be16_t src_port_mask_be,
	rte_be16_t dst_port_be, rte_be16_t dst_port_mask_be,
	uint8_t proto)
{
	int i;

	rule->data.category_mask = 0x1;
	rule->data.priority = 1;
	/* Userdata is filled in in register_ipv6_acl(). */

	rule->field[PROTO_FIELD_IPV6].value.u8 = proto;
	rule->field[PROTO_FIELD_IPV6].mask_range.u8 = 0xFF;

	for (i = DST1_FIELD_IPV6; i <= DST4_FIELD_IPV6; i++) {
		rule->field[i].value.u32 = rte_be_to_cpu_32(*dst_ip_be_ptr32);
		rule->field[i].mask_range.u32 = 32;
		dst_ip_be_ptr32++;
	}

	rule->field[SRCP_FIELD_IPV6].value.u16 = rte_be_to_cpu_16(src_port_be);
	rule->field[SRCP_FIELD_IPV6].mask_range.u16 =
		rte_be_to_cpu_16(src_port_mask_be);
	rule->field[DSTP_FIELD_IPV6].value.u16 = rte_be_to_cpu_16(dst_port_be);
	rule->field[DSTP_FIELD_IPV6].mask_range.u16 =
		rte_be_to_cpu_16(dst_port_mask_be);
}

int
ipv6_pkt_filter_add(struct gatekeeper_if *iface,
	const rte_be32_t *dst_ip_be_ptr32,
	rte_be16_t src_port_be, rte_be16_t src_port_mask_be,
	rte_be16_t dst_port_be, rte_be16_t dst_port_mask_be,
	uint8_t proto, __attribute__((unused)) uint16_t queue_id,
	acl_cb_func cb_f, ext_cb_func ext_cb_f,
	uint8_t *rx_method)
{
	/*
	 * XXX #466 The ntuple filter does not consistently
	 * work with IPv6 destination addresses, so we
	 * completely disable its usage and use an ACL instead.
	 */
	struct ipv6_acl_rule ipv6_rule = { };
	int ret;

	if (!ipv6_acl_enabled(iface)) {
		ret = init_ipv6_acls(iface);
		if (ret < 0)
			return ret;
	}

	ipv6_fill_acl_rule(&ipv6_rule, dst_ip_be_ptr32,
		src_port_be, src_port_mask_be,
		dst_port_be, dst_port_mask_be,
		proto);
	ret = register_ipv6_acl(&ipv6_rule,
		cb_f, ext_cb_f, iface);
	if (ret < 0) {
		G_LOG(ERR, "Could not register IPv6 ACL on the %s interface\n",
			iface->name);
		return ret;
	}
	*rx_method |= RX_METHOD_MB;

	return 0;
}

static uint32_t
find_num_numa_nodes(void)
{
	unsigned int i;
	uint32_t nb_numa_nodes = 0;

	RTE_LCORE_FOREACH(i) {
		uint32_t socket_id = rte_lcore_to_socket_id(i);
		if (nb_numa_nodes <= socket_id)
			nb_numa_nodes = socket_id + 1;
	}
	
	return nb_numa_nodes;
}

static int
configure_queue(const struct gatekeeper_if *iface, uint16_t queue_id,
	enum queue_type ty, struct rte_mempool *mp)
{
	uint16_t port_id = iface->id;

	/*
	 * The bonding driver (see file
	 * dependencies/dpdk/drivers/net/bonding/rte_eth_bond_pmd.c) passes
	 * rte_eth_dev_socket_id(port_id) for the parameter socket_id
	 * of rte_eth_rx_queue_setup() and rte_eth_tx_queue_setup().
	 *
	 * If @numa_node is not equal to rte_eth_dev_socket_id(port_id),
	 * the function rte_eth_dma_zone_reserve() will fail when
	 * when the driver of the NIC calls it.
	 *
	 * Although this issue is only raised while using the bonding driver,
	 * it makes sense to have the RX and TX queues on the same
	 * NUMA socket to which the underlying Ethernet device is connected.
	 */
	unsigned int numa_node = rte_eth_dev_socket_id(port_id);
	int ret;

	switch (ty) {
	case QUEUE_TYPE_RX:
		ret = rte_eth_rx_queue_setup(port_id, queue_id,
			iface->num_rx_desc, numa_node, NULL, mp);
		if (unlikely(ret < 0)) {
			G_LOG(ERR, "%s(%s): failed to configure RX queue %u (errno=%i): %s\n",
				__func__, iface->name, queue_id,
			       -ret, rte_strerror(-ret));
			return ret;
		}
		break;
	case QUEUE_TYPE_TX:
		ret = rte_eth_tx_queue_setup(port_id, queue_id,
			iface->num_tx_desc, numa_node, NULL);
		if (unlikely(ret < 0)) {
			G_LOG(ERR, "%s(%s): failed to configure TX queue %u (errno=%d): %s\n",
				__func__, iface->name, queue_id,
			       -ret, rte_strerror(-ret));
			return ret;
		}
		break;
	default:
		G_LOG(CRIT, "%s(%s): bug: unsupported queue type (%d)\n",
			__func__, iface->name, ty);
		return -EINVAL;
	}

	return 0;
}

static inline int
iface_bonded(struct gatekeeper_if *iface)
{
	return iface->num_ports > 1 ||
		iface->bonding_mode == BONDING_MODE_8023AD;
}

/*
 * Get a queue identifier for a given functional block instance (lcore),
 * using a certain interface for either RX or TX.
 */
int
get_queue_id(struct gatekeeper_if *iface, enum queue_type ty,
	unsigned int lcore, struct rte_mempool *mp)
{
	int16_t *queues, new_queue_id;
	int ret;

	if (unlikely(lcore >= RTE_MAX_LCORE || ty >= QUEUE_TYPE_MAX))
		return -EINVAL;

	queues = (ty == QUEUE_TYPE_RX) ? iface->rx_queues : iface->tx_queues;
	if (queues[lcore] != GATEKEEPER_QUEUE_UNALLOCATED)
		goto queue;

	/* Get next queue identifier. */
	new_queue_id = rte_atomic16_add_return(ty == QUEUE_TYPE_RX ?
		&iface->rx_queue_id : &iface->tx_queue_id, 1);
	if (unlikely(new_queue_id == GATEKEEPER_QUEUE_UNALLOCATED)) {
		G_LOG(ERR, "%s(%s): exhausted all %s queues; this is likely a bug\n",
			__func__, iface->name,
			(ty == QUEUE_TYPE_RX) ? "RX" : "TX");
		return -ENOSPC;
	}
	queues[lcore] = new_queue_id;

	ret = configure_queue(iface, new_queue_id, ty, mp);
	if (unlikely(ret < 0))
		return ret;

queue:
	return queues[lcore];
}

static void
close_iface_ports(struct gatekeeper_if *iface, uint8_t nb_ports)
{
	uint8_t i;
	for (i = 0; i < nb_ports; i++)
		rte_eth_dev_close(iface->ports[i]);
}

enum iface_destroy_cmd {
	/* Destroy only the data allocated by Lua. */
	IFACE_DESTROY_LUA,
	/* Destroy the data associated with initializing the ports. */
	IFACE_DESTROY_PORTS,
	/* Destroy the data initialized by the first phase of net config. */
	IFACE_DESTROY_INIT,
	/* Destroy data associated with running ports (stop them). */
	IFACE_DESTROY_STOP,
	/* Destroy all data for this interface. */
	IFACE_DESTROY_ALL,
};

static int
bonded_if_name(char *port_name, const struct gatekeeper_if *iface)
{
	/*
	 * The name of the bonded device must start with the name of
	 * the bonding driver. Otherwise, DPDK cannot identify
	 * the correct driver.
	 *
	 * The ID of the first port is used instead of the name of
	 * the interface (i.e. iface->name) because IF_NAMESIZE is
	 * small.
	 */
	int ret = snprintf(port_name, IF_NAMESIZE, "net_bonding%u",
		iface->ports[0]);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): snprintf() failed (errno=%i): %s\n",
			__func__, iface->name, -ret, strerror(-ret));
		return ret;
	}
	if (unlikely(ret >= IF_NAMESIZE)) {
		G_LOG(ERR, "%s(%s): port name is too long (len=%i)\n",
			__func__, iface->name, ret);
		return -ENOSPC;
	}
	return 0;
}

static void
destroy_iface(struct gatekeeper_if *iface, enum iface_destroy_cmd cmd)
{
	if (!iface->alive)
		return;

	switch (cmd) {
	case IFACE_DESTROY_ALL:
		/* Destroy the ACLs for each socket. */
		if (ipv6_acl_enabled(iface))
			destroy_acls(&iface->ipv6_acls);
		if (ipv4_acl_enabled(iface))
			destroy_acls(&iface->ipv4_acls);
		/* FALLTHROUGH */
	case IFACE_DESTROY_STOP:
		rte_eth_dev_stop(iface->id);
		/* FALLTHROUGH */
	case IFACE_DESTROY_INIT:
		/* FALLTHROUGH */
	case IFACE_DESTROY_PORTS:
		/* Stop and close bonded port, if needed. */
		if (iface_bonded(iface)) {
			char if_name[IF_NAMESIZE];
			int ret = bonded_if_name(if_name, iface);
			if (likely(ret == 0))
				rte_eth_bond_free(if_name);
		}

		/* Close and free interface ports. */
		close_iface_ports(iface, iface->num_ports);
		rte_free(iface->ports);
		iface->ports = NULL;
		/* FALLTHROUGH */
	case IFACE_DESTROY_LUA: {
		/* Free PCI addresses. */
		uint8_t i;
		for (i = 0; i < iface->num_ports; i++)
			rte_free(iface->pci_addrs[i]);
		rte_free(iface->pci_addrs);
		iface->pci_addrs = NULL;

		/* Free interface name. */
		rte_free(iface->name);
		iface->name = NULL;

		iface->alive = false;

		break;
	}
	default:
		rte_panic("Unexpected condition\n");
		break;
	}
}

int
get_ip_type(const char *ip_addr)
{
	int ret;
	struct addrinfo hint;
	struct addrinfo *res = NULL;

	memset(&hint, 0, sizeof(hint));

	hint.ai_family = PF_UNSPEC;
	hint.ai_flags = AI_NUMERICHOST;

	ret = getaddrinfo(ip_addr, NULL, &hint, &res);
	if (ret) {
		G_LOG(ERR, "net: invalid ip address %s; %s\n",
			ip_addr, gai_strerror(ret));
		return AF_UNSPEC;
	}

	if (res->ai_family != AF_INET && res->ai_family != AF_INET6)
		G_LOG(ERR, "net: %s is an is unknown address format %d\n",
			ip_addr, res->ai_family);

	ret = res->ai_family;
   	freeaddrinfo(res);

	return ret;
}

int
convert_str_to_ip(const char *ip_addr, struct ipaddr *res)
{
	int ip_type = get_ip_type(ip_addr);
	if (ip_type == AF_INET) {
		if (inet_pton(AF_INET, ip_addr, &res->ip.v4) != 1)
			return -1;

		res->proto = RTE_ETHER_TYPE_IPV4;
	} else if (likely(ip_type == AF_INET6)) {
		if (inet_pton(AF_INET6, ip_addr, &res->ip.v6) != 1)
			return -1;

		res->proto = RTE_ETHER_TYPE_IPV6;
	} else
		return -1;

	return 0;
}

int
convert_ip_to_str(const struct ipaddr *ip_addr, char *res, int n)
{
	if (ip_addr->proto == RTE_ETHER_TYPE_IPV4) {
		if (unlikely(inet_ntop(AF_INET, &ip_addr->ip.v4, res, n)
				== NULL)) {
			G_LOG(ERR, "%s(): failed to convert an IPv4 address to string (errno=%i): %s\n",
				__func__, errno, strerror(errno));
			return -1;
		}
		return 0;
	}

	if (likely(ip_addr->proto == RTE_ETHER_TYPE_IPV6)) {
		if (unlikely(inet_ntop(AF_INET6, &ip_addr->ip.v6, res, n)
				== NULL)) {
			G_LOG(ERR, "%s(): failed to convert an IPv6 address to string (errno=%i): %s\n",
				__func__, errno, strerror(errno));
			return -1;
		}
		return 0;
	}

	G_LOG(CRIT, "%s(): unexpected condition: unknown IP type %hu\n",
		__func__, ip_addr->proto);
	return -1;
}

static int
check_vlan_tag(const char *iface_name, uint16_t vlan_tag)
{
	if (vlan_tag > RTE_ETHER_MAX_VLAN_ID) {
		G_LOG(ERR, "net: VLAN ID %d of interface %s is too big; the maximum VLAN ID is %d\n",
			vlan_tag, iface_name, RTE_ETHER_MAX_VLAN_ID);
		return -1;
	}
	return 0;
}

int
lua_init_iface(struct gatekeeper_if *iface, const char *iface_name,
	const char **pci_addrs, uint8_t num_pci_addrs, const char **ip_cidrs,
	uint8_t num_ip_cidrs, uint16_t ipv4_vlan_tag, uint16_t ipv6_vlan_tag)
{
	uint8_t i, j;

	if (num_ip_cidrs < 1 || num_ip_cidrs > 2) {
		G_LOG(ERR,
			"net: an interface has at least 1 IP address, also at most 1 IPv4 and 1 IPv6 address.\n");
		return -1;
	}

	iface->num_ports = num_pci_addrs;

	iface->name = rte_malloc("iface_name", strlen(iface_name) + 1, 0);
	if (iface->name == NULL) {
		G_LOG(ERR, "net: %s: Out of memory for iface name\n",
			__func__);
		return -1;
	}
	strcpy(iface->name, iface_name);

	iface->pci_addrs = rte_calloc("pci_addrs", num_pci_addrs,
		sizeof(*pci_addrs), 0);
	if (iface->pci_addrs == NULL) {
		G_LOG(ERR, "net: %s: Out of memory for PCI array\n",
			__func__);
		goto name;
	}

	for (i = 0; i < num_pci_addrs; i++) {
		iface->pci_addrs[i] = rte_malloc(NULL,
			strlen(pci_addrs[i]) + 1, 0);
		if (iface->pci_addrs[i] == NULL) {
			G_LOG(ERR,
				"net: %s: Out of memory for PCI address %s\n",
				__func__, pci_addrs[i]);
			for (j = 0; j < i; j++)
				rte_free(iface->pci_addrs[j]);
			rte_free(iface->pci_addrs);
			iface->pci_addrs = NULL;
			goto name;
		}
		strcpy(iface->pci_addrs[i], pci_addrs[i]);
	}

	for (i = 0; i < num_ip_cidrs; i++) {
		/* Need to make copy to tokenize. */
		size_t ip_cidr_len = strlen(ip_cidrs[i]);
		char ip_cidr_copy[ip_cidr_len + 1];
		char *ip_addr;

		char *saveptr;
		char *prefix_len_str;
		char *end;
		long prefix_len;
		int gk_type;
		int max_prefix;

		strcpy(ip_cidr_copy, ip_cidrs[i]);

		ip_addr = strtok_r(ip_cidr_copy, "/", &saveptr);
		if (ip_addr == NULL)
			goto pci_addrs;

		gk_type = get_ip_type(ip_addr);
		if (gk_type == AF_INET &&
				inet_pton(AF_INET, ip_addr,
				&iface->ip4_addr) == 1) {
			iface->configured_proto |= CONFIGURED_IPV4;
		}
		else if (gk_type == AF_INET6 &&
				inet_pton(AF_INET6, ip_addr,
				&iface->ip6_addr) == 1) {
			/*
			 * According to RFC 6164, addresses with all zeros
			 * in the rightmost 64 bits SHOULD NOT be assigned as
			 * unicast addresses; addresses in which the rightmost
			 * 64 bits are assigned the highest 128 values
			 * (i.e., ffff:ffff:ffff:ff7f to ffff:ffff:ffff:ffff)
			 * SHOULD NOT be used as unicast addresses.
			 */
			uint64_t addr2 = rte_be_to_cpu_64(((rte_be64_t *)iface->ip6_addr.s6_addr)[1]);
			if (addr2 == 0 || addr2 >= 0xffffffffffffff7f) {
				G_LOG(ERR,
					"net: the rightmost 64 bits of the IP address %016" PRIx64 " SHOULD NOT be assigned to the interface\n",
					addr2);
				goto pci_addrs;
			}
			iface->configured_proto |= CONFIGURED_IPV6;
		}
		else
			goto pci_addrs;

		prefix_len_str = strtok_r(NULL, "\0", &saveptr);
		if (prefix_len_str == NULL)
			goto pci_addrs;

		prefix_len = strtol(prefix_len_str, &end, 10);
		if (prefix_len_str == end || !*prefix_len_str || *end) {
			G_LOG(ERR,
				"net: prefix length \"%s\" is not a number\n",
				prefix_len_str);
			goto pci_addrs;
		}
		if ((prefix_len == LONG_MAX || prefix_len == LONG_MIN) &&
				errno == ERANGE) {
			G_LOG(ERR,
				"net: prefix length \"%s\" caused underflow or overflow\n",
				prefix_len_str);
			goto pci_addrs;
		}

		max_prefix = max_prefix_len(gk_type) - 1;
		if (prefix_len < 0 || prefix_len > max_prefix) {
			G_LOG(ERR,
				"net: invalid prefix length \"%s\" on %s; must be in range [0, %d] to provide enough addresses for a valid deployment\n",
				prefix_len_str, ip_addr, max_prefix);
			goto pci_addrs;
		}

		if (gk_type == AF_INET) {
			ip4_prefix_mask(prefix_len, &iface->ip4_mask);
			iface->ip4_addr_plen = prefix_len;
		} else if (gk_type == AF_INET6) {
			ip6_prefix_mask(prefix_len, &iface->ip6_mask);
			iface->ip6_addr_plen = prefix_len;
		}
	}

	iface->l2_len_out = sizeof(struct rte_ether_hdr);
	if (iface->vlan_insert) {
		if (check_vlan_tag(iface_name, ipv4_vlan_tag) != 0 ||
				check_vlan_tag(iface_name, ipv6_vlan_tag) != 0)
			goto pci_addrs;

		iface->ipv4_vlan_tag_be = rte_cpu_to_be_16(ipv4_vlan_tag);
		iface->ipv6_vlan_tag_be = rte_cpu_to_be_16(ipv6_vlan_tag);
		iface->l2_len_out += sizeof(struct rte_vlan_hdr);
	}

	return 0;

pci_addrs:
	for (i = 0; i < num_pci_addrs; i++)
		rte_free(iface->pci_addrs[i]);
	rte_free(iface->pci_addrs);
	iface->pci_addrs = NULL;
name:
	rte_free(iface->name);
	iface->name = NULL;
	return -1;
}

struct net_config *
get_net_conf(void)
{
	return &config;
}

struct gatekeeper_if *
get_if_front(struct net_config *net_conf)
{
	return &net_conf->front;
}

struct gatekeeper_if *
get_if_back(struct net_config *net_conf)
{
	return net_conf->back_iface_enabled ? &net_conf->back : NULL;
}

static int
i40e_clear_inset_field(struct rte_pmd_i40e_inset *inset, uint8_t field_idx)
{
	int ret = rte_pmd_i40e_inset_field_clear(&inset->inset, field_idx);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(): cannot clear field %i\n",
			__func__, field_idx);
	}
	return ret;
}

static int
i40e_disable_ports_from_inset(uint16_t port_id,
	uint8_t pctype_id)
{
	struct rte_pmd_i40e_inset inset;

	/* Obtain the current RSS hash inset for @pctype_id. */
	int ret = rte_pmd_i40e_inset_get(port_id, pctype_id, &inset,
		INSET_HASH);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(port_id=%i, pctype=%i): cannot get inset (errno=%i): %s\n",
			__func__, port_id, pctype_id, -ret, rte_strerror(-ret));
		return ret;
	}

	/*
	 * Remove source port (i.e. first two bytes) of @pctype_id.
	 *
	 * Field index obtained at "Table 7-12. Default field vector table"
	 * of "Intel Ethernet Controller X710/XXV710/XL710 Datasheet".
	 *
	 * The field index below works for @pctype_id equals to TCP or UDP.
	 */
	ret = i40e_clear_inset_field(&inset, 29);
	if (unlikely(ret < 0))
		return ret;

	/*
	 * Remove destination port (i.e. third and forth bytes) of
	 * @pctype_id.
	 */
	ret = i40e_clear_inset_field(&inset, 30);
	if (unlikely(ret < 0))
		return ret;

	ret = rte_pmd_i40e_inset_set(port_id, pctype_id, &inset, INSET_HASH);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(port_id=%i, pctype=%i): cannot set inset (errno=%i): %s\n",
			__func__, port_id, pctype_id, -ret, rte_strerror(-ret));
	}
	return ret;
}

static int
i40e_disable_pctypes_ports_from_inset(uint16_t port_id, uint8_t *pctypes,
	uint8_t n)
{
	int i;
	for (i = 0; i < n; i++) {
		int ret = i40e_disable_ports_from_inset(port_id, pctypes[i]);
		if (unlikely(ret < 0))
			return ret;
	}
	return 0;
}

static int
i40e_disable_ipv4_tcp_udp_ports_from_inset(uint16_t port_id)
{
	/*
	 * PCTYPES obtained at "Table 7-5. Packet classifier types and
	 * its input sets" of "Intel Ethernet Controller X710/XXV710/XL710
	 * Datasheet".
	 */
	uint8_t pctypes[] = {
		31, /* Non-fragmented IPv4, UDP. */
		33, /* Non-fragmented IPv4, TCP. */
	};
	return i40e_disable_pctypes_ports_from_inset(port_id, pctypes,
		RTE_DIM(pctypes));
}

static int
i40e_disable_ipv6_tcp_udp_ports_from_inset(uint16_t port_id)
{
	/*
	 * PCTYPES obtained at "Table 7-5. Packet classifier types and
	 * its input sets" of "Intel Ethernet Controller X710/XXV710/XL710
	 * Datasheet".
	 */
	uint8_t pctypes[] = {
		41, /* Non-fragmented IPv6, UDP. */
		43, /* Non-fragmented IPv6, TCP. */
	};
	return i40e_disable_pctypes_ports_from_inset(port_id, pctypes,
		RTE_DIM(pctypes));
}

static int
randomize_rss_key(struct gatekeeper_if *iface)
{
	uint16_t final_set_count;
	unsigned int flags = iface->guarantee_random_entropy ? GRND_RANDOM : 0;

	/*
	 * To validate if the key generated is reasonable, the
	 * number of bits set to 1 in the key must be greater than
	 * 10% and less than 90% of the total bits in the key.
	 * min_num_set_bits and max_num_set_bits represent the lower
	 * and upper bound for the key.
	 */
	const uint16_t min_num_set_bits = iface->rss_key_len * 8 * 0.1;
	const uint16_t max_num_set_bits = iface->rss_key_len * 8 * 0.9;

	do {
		int number_of_bytes = 0;
		uint8_t i;

		/*
		 * When the last parameter of the system call getrandom()
		 * (i.e flags) is zero, getrandom() uses the /dev/urandom pool.
		 */
		do {
			int ret = getrandom(iface->rss_key + number_of_bytes,
				iface->rss_key_len - number_of_bytes, flags);
			if (ret < 0)
				return ret;
			number_of_bytes += ret;
		} while (number_of_bytes < iface->rss_key_len);

		final_set_count = 0;
		for (i = 0; i < iface->rss_key_len; i++) {
			final_set_count +=
				__builtin_popcount(iface->rss_key[i]);
		}
	} while (final_set_count < min_num_set_bits ||
			final_set_count > max_num_set_bits);
	return 0;
}

/*
 * Split up RTE_ETH_RSS_IP into IPv4-related and IPv6-related hash functions.
 * For each type of IP being used in Gatekeeper, check the supported
 * hashes of the device. If none are supported, disable RSS.
 * If RTE_ETH_RSS_IPV{4,6} is not supported, issue a warning since we expect
 * this to be a common and critical hash function. Some devices (i40e
 * and AVF) do not support the RTE_ETH_RSS_IPV{4,6} hashes, but the hashes
 * they do support may be enough.
 */

#define GATEKEEPER_IPV4_RSS_HF ( \
	RTE_ETH_RSS_IPV4 | \
	RTE_ETH_RSS_FRAG_IPV4 | \
	RTE_ETH_RSS_NONFRAG_IPV4_OTHER)

#define GATEKEEPER_IPV6_RSS_HF ( \
	RTE_ETH_RSS_IPV6 | \
	RTE_ETH_RSS_FRAG_IPV6 | \
	RTE_ETH_RSS_NONFRAG_IPV6_OTHER | \
	RTE_ETH_RSS_IPV6_EX)

static int
check_if_rss(struct gatekeeper_if *iface,
	const struct rte_eth_dev_info *dev_info, struct rte_eth_conf *port_conf)
{
	uint8_t rss_hash_key[GATEKEEPER_RSS_MAX_KEY_LEN];
	struct rte_eth_rss_conf __rss_conf = {
		.rss_key = rss_hash_key,
		.rss_key_len = sizeof(rss_hash_key),
	};
	uint64_t rss_off = dev_info->flow_type_rss_offloads;
	int ret;

	RTE_BUILD_BUG_ON((GATEKEEPER_IPV4_RSS_HF | GATEKEEPER_IPV6_RSS_HF) !=
		RTE_ETH_RSS_IP);

	/*
	 * Set up device RSS.
	 *
	 * Assume all ports support RSS until shown otherwise.
	 * If not, RSS will be disabled and only one queue is used.
	 *
	 * Check each port for the RSS hash functions it supports,
	 * and configure each to use the intersection of supported
	 * hash functions.
	 */
	iface->rss = true;
	port_conf->rx_adv_conf.rss_conf.rss_hf = 0;
	if (ipv4_if_configured(iface)) {
		port_conf->rx_adv_conf.rss_conf.rss_hf |=
			GATEKEEPER_IPV4_RSS_HF;
		if (iface->alternative_rss_hash)
			port_conf->rx_adv_conf.rss_conf.rss_hf |=
				RTE_ETH_RSS_NONFRAG_IPV4_TCP |
				RTE_ETH_RSS_NONFRAG_IPV4_UDP;
	}
	if (ipv6_if_configured(iface)) {
		port_conf->rx_adv_conf.rss_conf.rss_hf |=
			GATEKEEPER_IPV6_RSS_HF;
		if (iface->alternative_rss_hash)
			port_conf->rx_adv_conf.rss_conf.rss_hf |=
				RTE_ETH_RSS_NONFRAG_IPV6_TCP |
				RTE_ETH_RSS_NONFRAG_IPV6_UDP;
	}

	ret = rte_eth_dev_rss_hash_conf_get(iface->id, &__rss_conf);
	if (unlikely(ret == -ENOTSUP)) {
		G_LOG(WARNING, "%s(%s): interface did not return RSS configuration\n",
			__func__, iface->name);
		goto disable_rss;
	}

	/* Do not use @__rss_conf from now on. See issue #624 for details. */

	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): failed to get RSS hash configuration (errno=%i): %s\n",
			__func__, iface->name, -ret, rte_strerror(-ret));
		return ret;
	}
	RTE_VERIFY(ret == 0);

	/* This interface doesn't support RSS, so disable RSS. */
	if (unlikely(rss_off == 0)) {
		G_LOG(WARNING, "%s(%s): interface does not support RSS\n",
			__func__, iface->name);
		goto disable_rss;
	}

	/* Does Gatekeeper support the key length of @dev_info? */
	if (unlikely(dev_info->hash_key_size < GATEKEEPER_RSS_MIN_KEY_LEN ||
			dev_info->hash_key_size > GATEKEEPER_RSS_MAX_KEY_LEN ||
			dev_info->hash_key_size % 4 != 0)) {
		G_LOG(WARNING, "%s(%s): interface requires an RSS hash key of %i bytes; Gatekeeper only supports keys of [%i, %i] bytes long that are multiple of 4\n",
			__func__, iface->name, dev_info->hash_key_size,
			GATEKEEPER_RSS_MIN_KEY_LEN, GATEKEEPER_RSS_MAX_KEY_LEN);
		goto disable_rss;
	}
	iface->rss_key_len = dev_info->hash_key_size;

	if (unlikely(iface->alternative_rss_hash && iface_bonded(iface))) {
		G_LOG(ERR, "%s(%s): the parameter alternative_rss_hash cannot be true when the interface is bonded\n",
			__func__, iface->name);
		return -EINVAL;
	}

	/* Check IPv4 RSS hashes. */
	if (port_conf->rx_adv_conf.rss_conf.rss_hf & GATEKEEPER_IPV4_RSS_HF) {
		if (unlikely((rss_off & GATEKEEPER_IPV4_RSS_HF) == 0)) {
			G_LOG(WARNING, "%s(%s): interface does not support any IPv4 RSS hash\n",
				__func__, iface->name);
			goto disable_rss;
		}

		if (iface->alternative_rss_hash) {
			ret = i40e_disable_ipv4_tcp_udp_ports_from_inset(
				iface->id);
			if (unlikely(ret < 0)) {
				G_LOG(ERR, "%s(%s): i40e_disable_ipv4_tcp_udp_ports_from_inset() failed (errno=%i): %s\n",
					__func__, iface->name,
					-ret, rte_strerror(-ret));
				goto disable_rss;
			}
		} else if (unlikely((rss_off & RTE_ETH_RSS_IPV4) == 0)) {
			G_LOG(WARNING, "%s(%s): interface does not support the ETH_RSS_IPV4 hash function. The device may not hash packets to the correct queues; you may try the parameter alternative_rss_hash\n",
				__func__, iface->name);
		}
	}

	/* Check IPv6 RSS hashes. */
	if (port_conf->rx_adv_conf.rss_conf.rss_hf & GATEKEEPER_IPV6_RSS_HF) {
		if (unlikely((rss_off & GATEKEEPER_IPV6_RSS_HF) == 0)) {
			G_LOG(WARNING, "%s(%s): interface does not support any IPv6 RSS hash\n",
				__func__, iface->name);
			goto disable_rss;
		}

		if (iface->alternative_rss_hash) {
			ret = i40e_disable_ipv6_tcp_udp_ports_from_inset(
				iface->id);
			if (unlikely(ret < 0)) {
				G_LOG(ERR, "%s(%s): i40e_disable_ipv6_tcp_udp_ports_from_inset() failed (errno=%i): %s\n",
					__func__, iface->name,
					-ret, rte_strerror(-ret));
				goto disable_rss;
			}
		} else if (unlikely((rss_off & RTE_ETH_RSS_IPV6) == 0)) {
			G_LOG(WARNING, "%s(%s): interface does not support the ETH_RSS_IPV6 hash function. The device may not hash packets to the correct queues; you may try the parameter alternative_rss_hash\n",
				__func__, iface->name);
		}
	}

	/*
	 * Any missing hash that will cause RSS to definitely fail
	 * or are likely to cause RSS to fail are handled above.
	 * Here, also log if the device doesn't support any of the requested
	 * hashes, including the hashes considered non-essential.
	 */
	if ((rss_off & port_conf->rx_adv_conf.rss_conf.rss_hf) !=
			port_conf->rx_adv_conf.rss_conf.rss_hf) {
		G_LOG(WARNING, "%s(%s): interface only supports RSS hash functions 0x%"PRIx64", but Gatekeeper asks for 0x%"PRIx64"\n",
			__func__, iface->name, rss_off,
			port_conf->rx_adv_conf.rss_conf.rss_hf);
	}
	port_conf->rx_adv_conf.rss_conf.rss_hf &= rss_off;

	ret = randomize_rss_key(iface);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): failed to initialize RSS key (errno=%i): %s\n",
			__func__, iface->name, -ret, strerror(-ret));
		return ret;
	}

	/* Convert RSS key. */
	RTE_VERIFY(iface->rss_key_len % 4 == 0);
	rte_convert_rss_key((uint32_t *)iface->rss_key,
		(uint32_t *)iface->rss_key_be, iface->rss_key_len);

	port_conf->rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
	port_conf->rx_adv_conf.rss_conf.rss_key = iface->rss_key;
	port_conf->rx_adv_conf.rss_conf.rss_key_len = iface->rss_key_len;
	return 0;

disable_rss:
	iface->rss = false;
	port_conf->rx_adv_conf.rss_conf.rss_hf = 0;
	iface->num_rx_queues = 1;
	G_LOG(WARNING, "%s(%s): the interface does not have RSS capabilities; the GK or GT block will receive all packets and send them to the other blocks as needed. Gatekeeper or Grantor should only be run with one lcore dedicated to GK or GT in this mode; restart with only one GK or GT lcore if necessary\n",
		__func__, iface->name);
	return 0;
}

static int
check_if_mtu(struct gatekeeper_if *iface,
	const struct rte_eth_dev_info *dev_info, struct rte_eth_conf *port_conf)
{
	/*
	 * Set up device MTU.
	 *
	 * If greater than the size of the mbufs, then add the
	 * multi-segment buffer flag.
	 */
	port_conf->rxmode.mtu = iface->mtu;
	if (iface->mtu > RTE_MBUF_DEFAULT_BUF_SIZE)
		port_conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

	if (unlikely(dev_info->min_mtu > port_conf->rxmode.mtu)) {
		G_LOG(ERR, "%s(%s): the minimum MTU %u is larger than the configured MTU %"PRIu32"\n",
			__func__, iface->name,
			dev_info->min_mtu, port_conf->rxmode.mtu);
		return -EINVAL;
	}

	if (unlikely(dev_info->max_mtu < port_conf->rxmode.mtu)) {
		G_LOG(ERR, "%s(%s): the maximum MTU %u is smaller than the configured MTU %"PRIu32"\n",
			__func__, iface->name,
			dev_info->max_mtu, port_conf->rxmode.mtu);
		return -EINVAL;
	}

	if (unlikely((port_conf->txmode.offloads &
				RTE_ETH_TX_OFFLOAD_MULTI_SEGS) &&
			!(dev_info->tx_offload_capa &
			RTE_ETH_TX_OFFLOAD_MULTI_SEGS))) {
		G_LOG(NOTICE, "%s(%s): interface does not support offloading multi-segment TX buffers\n",
			__func__, iface->name);
		port_conf->txmode.offloads &= ~RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
	}

	return 0;
}

static int
check_if_checksums(struct gatekeeper_if *iface,
	const struct rte_eth_dev_info *dev_info, struct rte_eth_conf *port_conf)
{
	/*
	 * Set up checksumming.
	 *
	 * Gatekeeper and Grantor do IPv4 checksumming in hardware,
	 * if available.
	 *
	 * Grantor also does UDP checksumming in hardware, if available.
	 *
	 * In both cases, we set up the devices to assume that
	 * IPv4 and UDP checksumming are supported unless querying
	 * the device shows otherwise.
	 *
	 * Note that the IPv4 checksum field is only computed over
	 * the IPv4 header and the UDP checksum is computed over an IPv4
	 * pseudoheader (i.e. not the direct bytes of the IPv4 header).
	 * Therefore, even though offloading checksum computations can cause
	 * checksum fields to be set to 0 or an intermediate value during
	 * processing, the IPv4 and UDP checksum operations do not overlap,
	 * and can be configured as hardware or software independently.
	 */
	if (ipv4_if_configured(iface) && iface->ipv4_hw_cksum)
		port_conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
	if (!config.back_iface_enabled &&
			(iface->ipv4_hw_udp_cksum || iface->ipv6_hw_udp_cksum))
		port_conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

	if (unlikely((port_conf->txmode.offloads &
				RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) &&
			!(dev_info->tx_offload_capa &
			RTE_ETH_TX_OFFLOAD_IPV4_CKSUM))) {
		G_LOG(NOTICE, "%s(%s): interface does not support offloading IPv4 checksumming; using software IPv4 checksums\n",
			__func__, iface->name);
		port_conf->txmode.offloads &= ~RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
		iface->ipv4_hw_cksum = false;
	}

	if (unlikely((port_conf->txmode.offloads &
				RTE_ETH_TX_OFFLOAD_UDP_CKSUM) &&
			!(dev_info->tx_offload_capa &
			RTE_ETH_TX_OFFLOAD_UDP_CKSUM))) {
		G_LOG(NOTICE, "%s(%s): interface does not support offloading UDP checksumming; using software UDP checksums\n",
			__func__, iface->name);
		port_conf->txmode.offloads &= ~RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
		iface->ipv4_hw_udp_cksum = false;
		iface->ipv6_hw_udp_cksum = false;
	}

	return 0;
}

static int
check_if_offloads(struct gatekeeper_if *iface, struct rte_eth_conf *port_conf)
{
	struct rte_eth_dev_info dev_info;
	int ret = rte_eth_dev_info_get(iface->id, &dev_info);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): cannot obtain interface information (errno=%i): %s\n",
			__func__, iface->name, -ret, rte_strerror(-ret));
		return ret;
	}

	ret = check_if_rss(iface, &dev_info, port_conf);
	if (unlikely(ret < 0))
		return ret;

	ret = check_if_mtu(iface, &dev_info, port_conf);
	if (unlikely(ret < 0))
		return ret;

	ret = check_if_checksums(iface, &dev_info, port_conf);
	if (unlikely(ret < 0))
		return ret;

	return 0;
}

int
gatekeeper_setup_rss(uint16_t port_id, uint16_t *queues, uint16_t num_queues)
{
	int ret = 0;
	uint32_t i;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rss_reta_entry64 reta_conf[GATEKEEPER_RETA_MAX_SIZE];

	/* Get RSS redirection table (RETA) information. */
	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret < 0) {
		G_LOG(ERR, "%s(): cannot obtain information on port %hu (errno=%i): %s\n",
			__func__, port_id, -ret, rte_strerror(-ret));
		goto out;
	}
	if (dev_info.reta_size == 0) {
		G_LOG(ERR,
			"net: failed to setup RSS at port %hhu (invalid RETA size = 0)\n",
			port_id);
		ret = -1;
		goto out;
	}

	if (dev_info.reta_size > RTE_ETH_RSS_RETA_SIZE_512) {
		G_LOG(ERR,
			"net: failed to setup RSS at port %hhu (invalid RETA size = %u)\n",
			port_id, dev_info.reta_size);
		ret = -1;
		goto out;
	}

	/* Setup RSS RETA contents. */
	memset(reta_conf, 0, sizeof(reta_conf));

	for (i = 0; i < dev_info.reta_size; i++) {
		uint32_t idx = i / RTE_ETH_RETA_GROUP_SIZE;
		uint32_t shift = i % RTE_ETH_RETA_GROUP_SIZE;
		uint32_t queue_idx = i % num_queues; 

		/* Select all fields to set. */
		reta_conf[idx].mask = ~0LL;
		reta_conf[idx].reta[shift] = (uint16_t)queues[queue_idx];
	}

	/* RETA update. */
	ret = rte_eth_dev_rss_reta_update(port_id, reta_conf,
		dev_info.reta_size);
	if (ret == -ENOTSUP) {
		G_LOG(ERR,
			"net: failed to setup RSS at port %hhu hardware doesn't support\n",
			port_id);
		ret = -1;
		goto out;
	} else if (ret == -EINVAL) {
		G_LOG(ERR,
			"net: failed to setup RSS at port %hhu (RETA update with bad redirection table parameter)\n",
			port_id);
		ret = -1;
		goto out;
	}

	/* RETA query. */
	ret = rte_eth_dev_rss_reta_query(port_id, reta_conf,
		dev_info.reta_size);
	if (ret == -ENOTSUP) {
		G_LOG(ERR,
			"net: failed to setup RSS at port %hhu hardware doesn't support\n",
			port_id);
		ret = -1;
	} else if (ret == -EINVAL) {
		G_LOG(ERR,
			"net: failed to setup RSS at port %hhu (RETA query with bad redirection table parameter)\n",
			port_id);
		ret = -1;
	}

out:
	return ret;
}

int
gatekeeper_get_rss_config(uint16_t port_id,
	struct gatekeeper_rss_config *rss_conf)
{
	uint16_t i;
	struct rte_eth_dev_info dev_info;

	/* Get RSS redirection table (RETA) information. */
	int ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret < 0) {
		G_LOG(ERR, "%s(): cannot obtain information on port %hu (errno=%i): %s\n",
			__func__, port_id, -ret, rte_strerror(-ret));
		goto out;
	}
	rss_conf->reta_size = dev_info.reta_size;
	if (rss_conf->reta_size == 0 ||
			rss_conf->reta_size > RTE_ETH_RSS_RETA_SIZE_512) {
		G_LOG(ERR,
			"net: failed to setup RSS at port %hhu (invalid RETA size = %hu)\n",
			port_id, rss_conf->reta_size);
		ret = -1;
		goto out;
	}

	for (i = 0; i < dev_info.reta_size; i++) {
		uint32_t idx = i / RTE_ETH_RETA_GROUP_SIZE;
		/* Select all fields to query. */
		rss_conf->reta_conf[idx].mask = ~0LL;
	}

	/* RETA query. */
	ret = rte_eth_dev_rss_reta_query(port_id,
		rss_conf->reta_conf, rss_conf->reta_size);
	if (ret == -ENOTSUP) {
		G_LOG(ERR,
			"net: failed to query RSS configuration at port %hhu hardware doesn't support\n",
			port_id);
		ret = -1;
	} else if (ret == -EINVAL) {
		G_LOG(ERR,
			"net: failed to query RSS configuration at port %hhu (RETA query with bad redirection table parameter)\n",
			port_id);
		ret = -1;
	}

out:
	return ret;
}

int
gatekeeper_setup_user(struct net_config *net_conf, const char *user)
{
	struct passwd *pw;

	if (user == NULL) {
		net_conf->pw_uid = 0;
		net_conf->pw_gid = 0;
		return 0;
	}

	if ((pw = getpwnam(user)) == NULL) {
		G_LOG(ERR, "%s: failed to call getpwnam() for user %s - %s\n",
			__func__, user, strerror(errno));
		return -1;
	}

	net_conf->pw_uid = pw->pw_uid;
	net_conf->pw_gid = pw->pw_gid;
	return 0;
}

static int
create_bond(struct gatekeeper_if *iface)
{
	char dev_name[IF_NAMESIZE];
	unsigned int i;
	int ret2, ret = bonded_if_name(dev_name, iface);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): cannot name bonded port (errno=%i): %s\n",
			__func__, iface->name, -ret, strerror(-ret));
		return ret;
	}

	ret = rte_eth_bond_create(dev_name, iface->bonding_mode,
		rte_eth_dev_socket_id(iface->ports[0]));
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): failed to create bonded port (errno=%i): %s\n",
			__func__, iface->name, -ret, rte_strerror(-ret));
		return ret;
	}
	iface->id = ret;

	if (__lacp_enabled(iface)) {
		/*
		 * If LACP is enabled, enable multicast addresses.
		 * Otherwise, rx_burst_8023ad() of DPDK's bonding driver
		 * (see rte_eth_bond_pmd.c) is going to discard
		 * multicast Ethernet packets such as ARP and
		 * ND packets.
		 */
		ret = rte_eth_allmulticast_enable(iface->id);
		if (unlikely(ret < 0)) {
			G_LOG(ERR, "%s(%s): cannot enable multicast on bond device (errno=%i): %s\n",
				__func__, iface->name,
				-ret, rte_strerror(-ret));
			goto close_bond;
		}
	}

	/* Add members to bond. */
	for (i = 0; i < iface->num_ports; i++) {
		ret = rte_eth_bond_member_add(iface->id, iface->ports[i]);
		if (unlikely(ret < 0)) {
			G_LOG(ERR, "%s(%s): failed to add member %u (errno=%i): %s\n",
				__func__, iface->name, iface->ports[i],
				-ret, rte_strerror(-ret));
			goto close_bond;
		}
	}

	if (__lacp_enabled(iface) && iface->num_ports > 1) {
		/*
		 * XXX #686 Ensure that all members can receive packets
		 * destined to the MAC address of the bond.
		 *
		 * This must come after adding members. Otherwise,
		 * rte_eth_dev_mac_addr_add() unfortunately does nothing.
		 */
		struct rte_ether_addr if_macaddr;
		ret = rte_eth_macaddr_get(iface->id, &if_macaddr);
		if (unlikely(ret < 0)) {
			G_LOG(ERR, "%s(%s): cannot get MAC address (errno=%i): %s\n",
				__func__, iface->name,
				-ret, rte_strerror(-ret));
			goto close_bond;
		}
		ret = rte_eth_dev_mac_addr_add(iface->id, &if_macaddr, 0);
		if (unlikely(ret < 0)) {
			G_LOG(ERR, "%s(%s): cannot add interface MAC address (errno=%i): %s\n",
				__func__, iface->name,
				-ret, rte_strerror(-ret));
			goto close_bond;
		}
	}

	return 0;

close_bond:
	ret2 = rte_eth_bond_free(dev_name);
	if (unlikely(ret2 < 0)) {
		G_LOG(WARNING, "%s(%s): rte_eth_bond_free() failed (errno=%i): %s\n",
			__func__, iface->name, -ret2, rte_strerror(-ret2));
	}
	return ret;
}

static int
init_iface(struct gatekeeper_if *iface)
{
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.mq_mode = RTE_ETH_MQ_RX_NONE,
		},
		/* Other offloads configured below. */
	};
	unsigned int i;
	int ret;

	iface->alive = true;

	/* Initialize all potential queues on this interface. */
	for (i = 0; i < RTE_MAX_LCORE; i++) {
		iface->rx_queues[i] = GATEKEEPER_QUEUE_UNALLOCATED;
		iface->tx_queues[i] = GATEKEEPER_QUEUE_UNALLOCATED;
	}
	rte_atomic16_set(&iface->rx_queue_id, -1);
	rte_atomic16_set(&iface->tx_queue_id, -1);

	iface->ports = rte_calloc("ports", iface->num_ports,
		sizeof(*iface->ports), 0);
	if (unlikely(iface->ports == NULL)) {
		G_LOG(ERR, "%s(%s): out of memory for ports\n",
			__func__, iface->name);
		destroy_iface(iface, IFACE_DESTROY_LUA);
		return -ENOMEM;
	}

	/* Initialize all ports on this interface. */
	for (i = 0; i < iface->num_ports; i++) {
		ret = rte_eth_dev_get_port_by_name(iface->pci_addrs[i],
			&iface->ports[i]);
		if (unlikely(ret < 0)) {
			G_LOG(ERR, "%s(%s): failed to map PCI %s to a port (errno=%i): %s\n",
				__func__, iface->name, iface->pci_addrs[i],
				-ret, rte_strerror(-ret));
			goto free_ports;
		}
	}

	/* Initialize bonded port, if needed. */
	if (!iface_bonded(iface)) {
		RTE_VERIFY(iface->num_ports == 1);
		iface->id = iface->ports[0];
	} else {
		ret = create_bond(iface);
		if (unlikely(ret < 0))
			goto free_ports;
	}

	/* Make sure the interface supports hardware offloads. */
	ret = check_if_offloads(iface, &port_conf);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): interface doesn't support a critical hardware capability (errno=%i): %s\n",
			__func__, iface->name, -ret, strerror(-ret));
		goto close_ports;
	}

	ret = rte_eth_dev_configure(iface->id, iface->num_rx_queues,
		iface->num_tx_queues, &port_conf);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): failed to configure interface (errno=%i): %s\n",
			__func__, iface->name, -ret, rte_strerror(-ret));
		goto close_ports;
	}

	return 0;

close_ports:
	destroy_iface(iface, IFACE_DESTROY_PORTS);
	return ret;
free_ports:
	rte_free(iface->ports);
	iface->ports = NULL;
	destroy_iface(iface, IFACE_DESTROY_LUA);
	return ret;
}

static int
start_port(uint8_t port_id, uint8_t *pnum_succ_ports,
	unsigned int num_attempts_link_get)
{
	struct rte_eth_link link;
	uint8_t attempts = 0;

	/* Start device. */
	int ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		G_LOG(ERR, "net: failed to start port %hhu (err=%d)\n",
			port_id, ret);
		return ret;
	}
	if (pnum_succ_ports != NULL)
		(*pnum_succ_ports)++;

	/*
	 * The following code ensures that the device is ready for
	 * full speed RX/TX.
	 *
	 * When the initialization is done without this,
	 * the initial packet transmission may be blocked.
	 *
	 * Optionally, we can wait for the link to come up before
	 * continuing. This is useful for bonded ports where the
	 * slaves must be activated after starting the bonded
	 * device in order for the link to come up. The slaves
	 * are activated on a timer, so this can take some time.
	 */
	do {
		ret = rte_eth_link_get(port_id, &link);
		if (ret < 0) {
			G_LOG(ERR, "net: querying port %hhu failed with err - %s\n",
				port_id, rte_strerror(-ret));
			return ret;
		}
		RTE_VERIFY(ret == 0);

		/* Link is up. */
		if (link.link_status)
			break;

		G_LOG(ERR, "net: querying port %hhu, and link is down\n",
			port_id);

		if (attempts > num_attempts_link_get) {
			G_LOG(ERR, "net: giving up on port %hhu\n", port_id);
			return -1;
		}

		attempts++;
		sleep(1);
	} while (true);

	return 0;
}

static inline void
gen_ipv6_link_local(struct gatekeeper_if *iface)
{
	/* Link-local IPv6 calculation according to RFC 4291. */
	struct in6_addr *addr = &iface->ll_ip6_addr;
	uint64_t *pmask = (uint64_t *)iface->ll_ip6_mask.s6_addr;

	addr->s6_addr[0] = 0xFE;
	addr->s6_addr[1] = 0x80;
	memset(addr->s6_addr + 2, 0, 6);

	rte_memcpy(addr->s6_addr + 8, iface->eth_addr.addr_bytes, 3);
	addr->s6_addr[11] = 0xFF;
	addr->s6_addr[12] = 0xFE;
	rte_memcpy(addr->s6_addr + 13, iface->eth_addr.addr_bytes + 3, 3);

	addr->s6_addr[8] ^= 2;

	pmask[0] = ~0ULL;
	pmask[1] = 0ULL;
}

/*
 * Setup the various IPv6 addresses that represent this host.
 * Needed whenever IPv6 is configured.
 *
 * Note: must be called after the interface's MAC address is
 * fetched (for the link local address), which can only happen
 * after the interface is started.
 */
static void
setup_ipv6_addrs(struct gatekeeper_if *iface)
{
	/*
	 * Generate and assign IPv6 solicited-node multicast
	 * address for our global address.
	 */
	uint8_t ip6_mc_addr[16] = IPV6_SN_MC_ADDR(iface->ip6_addr.s6_addr);
	struct rte_ether_addr eth_mc_addr = {
		.addr_bytes = {
			           0x33,            0x33,
			ip6_mc_addr[12], ip6_mc_addr[13],
			ip6_mc_addr[14], ip6_mc_addr[15],
		},
	};
	rte_memcpy(iface->ip6_mc_addr.s6_addr, ip6_mc_addr,
		sizeof(iface->ip6_mc_addr.s6_addr));
	rte_ether_addr_copy(&eth_mc_addr, &iface->eth_mc_addr);

	/*
	 * Generate a link-local address, and then use it to
	 * generate a solicited-node multicast address for
	 * that link-local address.
	 */
	gen_ipv6_link_local(iface);
	{
		uint8_t ll_ip6_mc_addr[16] =
			IPV6_SN_MC_ADDR(iface->ll_ip6_addr.s6_addr);
		struct rte_ether_addr ll_eth_mc_addr = {
			.addr_bytes = {
				              0x33,               0x33,
				ll_ip6_mc_addr[12], ll_ip6_mc_addr[13],
				ll_ip6_mc_addr[14], ll_ip6_mc_addr[15],
			},
		};
		struct rte_ether_addr mc_addrs[2] =
			{ eth_mc_addr, ll_eth_mc_addr };
		rte_memcpy(iface->ll_ip6_mc_addr.s6_addr, ll_ip6_mc_addr,
			sizeof(iface->ll_ip6_mc_addr.s6_addr));
		rte_ether_addr_copy(&ll_eth_mc_addr, &iface->ll_eth_mc_addr);

		/* Add to list of accepted MAC addresses. */
		rte_eth_dev_set_mc_addr_list(iface->id, mc_addrs, 2);
	}
}

static int
check_if_rss_key_update(const struct gatekeeper_if *iface)
{
	struct rte_eth_dev_info dev_info;
	uint8_t rss_hash_key[GATEKEEPER_RSS_MAX_KEY_LEN];
	struct rte_eth_rss_conf rss_conf = {
		.rss_key = rss_hash_key,
		.rss_key_len = sizeof(rss_hash_key),
	};
	int ret;

	if (!iface->rss)
		return 0;

	ret = rte_eth_dev_info_get(iface->id, &dev_info);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): cannot obtain interface information (errno=%i): %s\n",
			__func__, iface->name, -ret, rte_strerror(-ret));
		return ret;
	}

	ret = rte_eth_dev_rss_hash_conf_get(iface->id, &rss_conf);
	switch (ret) {
	case 0:
		break;
	case -ENODEV:
		G_LOG(WARNING, "%s(%s): failed to get RSS hash configuration: interface identifier is invalid\n",
			__func__, iface->name);
		return ret;
	case -EIO:
		G_LOG(WARNING, "%s(%s): failed to get RSS hash configuration: device is removed\n",
			__func__, iface->name);
		return ret;
	case -ENOTSUP:
		G_LOG(WARNING, "%s(%s): failed to get RSS hash configuration: hardware does not support RSS\n",
			__func__, iface->name);
		return ret;
	default:
		G_LOG(WARNING, "%s(%s): failed to get RSS hash configuration (errno=%i): %s\n",
			__func__, iface->name, -ret, rte_strerror(-ret));
		return ret;
	}

	/*
	 * XXX #624 Use @dev_info.hash_key_size instead of
	 * @rss_conf.rss_key_len to avoid a bug in DPDK.
	 */
	if (unlikely(dev_info.hash_key_size != iface->rss_key_len ||
			memcmp(rss_conf.rss_key, iface->rss_key,
				iface->rss_key_len) != 0)) {
		G_LOG(WARNING, "%s(%s): the obtained RSS hash configuration does not match the expected RSS configuration\n",
			__func__, iface->name);
		return -EINVAL;
	}

	return 0;
}

static int
start_iface(struct gatekeeper_if *iface, unsigned int num_attempts_link_get)
{
	int ret = start_port(iface->id, NULL, num_attempts_link_get);
	if (unlikely(ret < 0)) {
		destroy_iface(iface, IFACE_DESTROY_INIT);
		return ret;
	}

	/*
	 * If we try to update/get the RSS hash configuration before
	 * the start of the NICs, no meaningful operations will be
	 * done; even the return values indicate no errors.
	 *
	 * After checking the source code of DPDK library,
	 * it turns out that RSS is disabled in the MRQC register
	 * before we start the NICs.
	 *
	 * Only after the NICs start, we can check whether the RSS hash
	 * is configured correctly or not.
	 */
	ret = check_if_rss_key_update(iface);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): port does not have the correct RSS hash key (errno=%i): %s\n",
			__func__, iface->name, -ret, strerror(-ret));
		goto stop;
	}

	ret = rte_eth_macaddr_get(iface->id, &iface->eth_addr);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): cannot get MAC address (errno=%i): %s\n",
			__func__, iface->name, -ret, rte_strerror(-ret));
		goto stop;
	}

	if (ipv6_if_configured(iface))
		setup_ipv6_addrs(iface);

	return 0;

stop:
	destroy_iface(iface, IFACE_DESTROY_STOP);
	return ret;
}

unsigned int
calculate_mempool_config_para(const char *block_name,
	struct net_config *net_conf, unsigned int total_pkt_burst)
{
	unsigned int num_mbuf;

	/*
	 * The total number of receive descriptors to
	 * allocate per lcore for the receive ring over all interfaces.
	 */
	uint16_t total_rx_desc = net_conf->front.num_rx_desc +
		(net_conf->back_iface_enabled ? net_conf->back.num_rx_desc : 0);

	/*
	 * The total number of transmit descriptors to
	 * allocate per lcore for the transmit ring over all interfaces.
	 */
	uint16_t total_tx_desc = net_conf->front.num_tx_desc +
		(net_conf->back_iface_enabled ? net_conf->back.num_tx_desc : 0);

	/*
	 * The number of elements in the mbuf pool.
	 *
	 * Need to provision enough memory for the worst case.
	 * It's the number of RX descriptors, the number of TX descriptors,
	 * and the number of packet burst buffers.
	 */
	uint32_t max_num_pkt = total_rx_desc + total_tx_desc + total_pkt_burst;

	/*
	 * The optimum size (in terms of memory usage) for a mempool is when
	 * it is a power of two minus one.
	 */
	num_mbuf = rte_align32pow2(max_num_pkt) - 1;

	G_LOG(NOTICE, "%s: %s: total_pkt_burst = %hu packets, total_rx_desc = %hu descriptors, total_tx_desc = %hu descriptors, max_num_pkt = %u packets, num_mbuf = %u packets.\n",
		block_name, __func__, total_pkt_burst, total_rx_desc,
		total_tx_desc, max_num_pkt, num_mbuf);

	return num_mbuf;
}

struct rte_mempool *
create_pktmbuf_pool(const char *block_name, unsigned int lcore,
	unsigned int num_mbuf)
{
	struct rte_mempool *mp;
	char pool_name[64];
	int ret = snprintf(pool_name, sizeof(pool_name), "pktmbuf_pool_%s_%u",
		block_name, lcore);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(pool_name));
	mp = rte_pktmbuf_pool_create_by_ops(pool_name, num_mbuf, 0,
		sizeof(struct sol_mbuf_priv), RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_lcore_to_socket_id(lcore), "ring_mp_sc");
	if (mp == NULL) {
		G_LOG(ERR,
			"net: failed to allocate mbuf for block %s at lcore %u\n",
			block_name, lcore);

		if (rte_errno == E_RTE_NO_CONFIG) G_LOG(ERR, "function could not get pointer to rte_config structure\n");
		else if (rte_errno == E_RTE_SECONDARY) G_LOG(ERR, "function was called from a secondary process instance\n");
		else if (rte_errno == EINVAL) G_LOG(ERR, "cache size provided is too large\n");
		else if (rte_errno == ENOSPC) G_LOG(ERR, "the maximum number of memzones has already been allocated\n");
		else if (rte_errno == EEXIST) G_LOG(ERR, "a memzone with the same name already exists\n");
		else if (rte_errno == ENOMEM) G_LOG(ERR, "no appropriate memory area found in which to create memzone\n");
		else G_LOG(ERR, "unknown error creating mbuf pool\n");

		return NULL;
	}

	return mp;
}

static int
init_iface_stage1(void *arg)
{
	struct gatekeeper_if *iface = arg;
	return init_iface(iface);
}

static int
start_network_stage2(void *arg)
{
	struct net_config *net = arg;
	int ret = start_iface(&net->front, net->num_attempts_link_get);
	if (unlikely(ret < 0))
		goto fail;

	if (net->back_iface_enabled) {
		ret = start_iface(&net->back, net->num_attempts_link_get);
		if (unlikely(ret < 0))
			goto destroy_front;
	}

	return 0;

destroy_front:
	destroy_iface(&net->front, IFACE_DESTROY_STOP);
fail:
	G_LOG(ERR, "%s(): failed to start Gatekeeper network\n", __func__);
	return ret;
}

static int
copy_amb_to_inh(cap_t cap_p)
{
	cap_value_t i;

	for (i = 0; i <= CAP_LAST_CAP; i++) {
		char *cap_name;
		int old_errno;
		int ret;

		int value = cap_get_ambient(i);
		if (value < 0) {
			old_errno = errno;
			cap_name = cap_to_name(i);
			if (cap_name == NULL) {
				G_LOG(WARNING, "%s(): could not get string for capability %u (%s) while reporting that it is not supported by the running kernel (%s)\n",
					__func__, i, strerror(errno),
					strerror(old_errno));
				continue;
			}

			G_LOG(WARNING, "%s(): capability %s (%u) not supported by the running kernel: %s\n",
				__func__, cap_name, i, strerror(old_errno));
			cap_free(cap_name);
			continue;
		}

		ret = cap_set_flag(cap_p, CAP_INHERITABLE, 1, &i,
			value ? CAP_SET : CAP_CLEAR);
		if (ret != 0) {
			old_errno = errno;
			cap_name = cap_to_name(i);
			if (cap_name == NULL) {
				G_LOG(WARNING, "%s(): could not get string for capability %u (%s) while reporting that it could not be set to CAP_INHERITABLE (%s)\n",
					__func__, i, strerror(errno),
					strerror(old_errno));
				continue;
			}

			G_LOG(ERR, "%s(): could not set CAP_INHERITABLE to %u for capability %s (%u): %s\n",
				__func__, value ? CAP_SET : CAP_CLEAR,
				cap_name, i, strerror(old_errno));
			cap_free(cap_name);
			return -1;
		}
	}

	return 0;
}

static void
log_proc_caps(const char *context)
{
	cap_t cap_p = cap_get_proc();
	char *cap_output, *amb_output;
	int ret;

	if (cap_p == NULL) {
		G_LOG(ERR, "%s(): cannot get capabilities: %s\n",
			__func__, strerror(errno));
		return;
	}

	cap_output = cap_to_text(cap_p, NULL);
	if (cap_output == NULL) {
		G_LOG(ERR, "%s(): cannot get text string of capabilities: %s\n",
			__func__, strerror(errno));
		goto proc;
	}

	if (!CAP_AMBIENT_SUPPORTED()) {
		G_LOG(DEBUG, "%s: %s\n", context, cap_output);
		goto cap;
	}

	/* Log ambient capabilities. */
	cap_clear(cap_p);
	ret = copy_amb_to_inh(cap_p);
	if (ret < 0)
		goto cap;

	amb_output = cap_to_text(cap_p, NULL);
	if (amb_output == NULL) {
		G_LOG(ERR, "%s(): cannot get text string of ambient capabilities: %s\n",
			__func__, strerror(errno));
		goto cap;
	}

	G_LOG(DEBUG, "%s: %s\t(ambient as inheritable): %s\n",
		context, cap_output, amb_output);

	cap_free(amb_output);
cap:
	cap_free(cap_output);
proc:
	cap_free(cap_p);
}

int
needed_caps(int ncap, const cap_value_t *caps)
{
	cap_t cap_p;
	int ret;

	/* No capablities are needed when run as root. */
	if (config.pw_uid == 0)
		return 0;

	log_proc_caps("Capabilities before setting");

	cap_p = cap_init();
	if (cap_p == NULL) {
		G_LOG(ERR, "%s(): could not create a capability state in working storage: %s\n",
			__func__, strerror(errno));
		return -1;
	}

	if (ncap > 0) {
		ret = cap_set_flag(cap_p, CAP_PERMITTED, ncap, caps, CAP_SET);
		if (ret != 0) {
			G_LOG(ERR, "%s(): could not set CAP_PERMITTED for %d capabilities: %s\n",
				__func__, ncap, strerror(errno));
			goto free;
		}

		ret = cap_set_flag(cap_p, CAP_EFFECTIVE, ncap, caps, CAP_SET);
		if (ret != 0) {
			G_LOG(ERR, "%s(): could not set CAP_EFFECTIVE for %d capabilities: %s\n",
				__func__, ncap, strerror(errno));
			goto free;
		}
	}

	ret = cap_set_proc(cap_p);
	if (ret != 0) {
		G_LOG(ERR, "%s(): could not set capabilities for process: %s\n",
			__func__, strerror(errno));
		goto free;
	}
free:
	cap_free(cap_p);

	if (ret < 0)
		return ret;

	if (CAP_AMBIENT_SUPPORTED()) {
		ret = cap_reset_ambient();
		if (ret != 0) {
			G_LOG(ERR, "%s(): could not reset ambient capabilities: %s\n",
				__func__, strerror(errno));
		}
	}

	log_proc_caps("Capabilities after setting");

	return ret;
}

static int
set_groups(const char *user, gid_t gid)
{
	int ret;
	int old_num_gids, num_gids = 0;
	gid_t *gids;

	/* Fetch number of groups this user is a member of. */
	ret = getgrouplist(user, gid, NULL, &num_gids);
	if (ret != -1) {
		G_LOG(ERR, "%s: getgrouplist indicates user %s is not in any groups, but belongs to at least %d\n",
			__func__, user, gid);
		return -1;
	}
	RTE_VERIFY(num_gids >= 0);

	if (num_gids == 0) {
		/* User belongs to no groups. */
		ret = cap_setgroups(gid, 0, NULL);
		if (ret == -1) {
			G_LOG(ERR, "%s: could not assign empty group set with cap_setgroups: %s\n",
				__func__, strerror(errno));
			return -1;
		}
		return 0;
	}

	gids = rte_malloc("gids", num_gids * sizeof(*gids), 0);
	if (gids == NULL) {
		G_LOG(ERR, "%s: could not allocate memory for the %d groups of user %s\n",
			__func__, num_gids, user);
		return -1;
	}

	old_num_gids = num_gids;
	ret = getgrouplist(user, gid, gids, &num_gids);
	if (ret != old_num_gids) {
		G_LOG(ERR, "%s: expected %d groups but received %d from getgrouplist\n",
			__func__, old_num_gids, ret);
		ret = -1;
		goto free;
	}

	ret = cap_setgroups(gid, num_gids, gids);
	if (ret == -1) {
		G_LOG(ERR, "%s: could not set the groups of user %s with cap_setgroups: %s\n",
			__func__, user, strerror(errno));
	}
free:
	rte_free(gids);
	return ret;
}

static int
change_user(void)
{
	struct passwd *pw;
	int ret;

	errno = 0;
	pw = getpwuid(config.pw_uid);
	if (pw == NULL) {
		G_LOG(ERR, "%s: failed to get the passwd struct for uid %u - %s\n",
			__func__, config.pw_uid,
			errno != 0 ? strerror(errno) : "user not found");
		return -1;
	}

	G_LOG(DEBUG, "Ambient capabilities supported: %s\n",
		CAP_AMBIENT_SUPPORTED() ? "yes" : "no");

	log_proc_caps("Capabilities before changing privileges");

	ret = set_groups(pw->pw_name, config.pw_gid);
	if (ret < 0) {
		G_LOG(ERR, "%s: failed to set groups for user %s (gid %d)\n",
			__func__, pw->pw_name, config.pw_gid);
		return -1;
	}

	log_proc_caps("Capabilities after changing group(s)");

	ret = cap_setuid(config.pw_uid);
	if (ret != 0) {
		G_LOG(ERR, "%s: failed to set UID for user %s (uid %d): %s\n",
			__func__, pw->pw_name, config.pw_uid, strerror(errno));
		return -1;
	}

	log_proc_caps("Capabilities after changing user");

	if (seteuid(0) != -1) {
		G_LOG(ERR, "%s: seteuid() was able to set the effective ID of a non-root user to root\n",
			__func__);
		return -1;
	}

	if (setegid(0) != -1) {
		G_LOG(ERR, "%s: setegid() was able to set the effective group ID of a non-root user to root\n",
			__func__);
		return -1;
	}

	return 0;
}

int
finalize_stage2(void *arg)
{
	int ret;

	if (ipv4_acl_enabled(&config.front)) {
		ret = build_ipv4_acls(&config.front);
		if (ret < 0)
			return ret;
	}
	if (ipv4_acl_enabled(&config.back)) {
		ret = build_ipv4_acls(&config.back);
		if (ret < 0)
			return ret;
	}
	if (ipv6_acl_enabled(&config.front)) {
		ret = build_ipv6_acls(&config.front);
		if (ret < 0)
			return ret;
	}
	if (ipv6_acl_enabled(&config.back)) {
		ret = build_ipv6_acls(&config.back);
		if (ret < 0)
			return ret;
	}
	if (config.pw_uid != 0) {
		int log_fd = (intptr_t)arg;
		ret = fchown(log_fd, config.pw_uid, config.pw_gid);
		if (ret != 0) {
			G_LOG(ERR, "Failed to change the owner of the file (with descriptor %d) to user with uid %u and gid %u - %s\n",
				log_fd, config.pw_uid,
				config.pw_gid, strerror(errno));
			return ret;
		}

		ret = change_user();
		if (ret != 0)
			return ret;
	}

	G_LOG(NOTICE, "Gatekeeper pid = %u\n", getpid());

	/* Enable rate-limited logging now that startup is complete. */
	log_ratelimit_enable();

	return 0;
}

static bool
ipv4_test_same_subnet(struct net_config *net)
{
	const uint32_t ip4_mask =
		net->front.ip4_addr_plen <= net->back.ip4_addr_plen
			? net->front.ip4_mask.s_addr
			: net->back.ip4_mask.s_addr;
	return ip4_same_subnet(net->front.ip4_addr.s_addr,
		net->back.ip4_addr.s_addr, ip4_mask);
}

static bool
ipv6_test_same_subnet(struct net_config *net)
{
	const struct in6_addr *ip6_mask =
		net->front.ip6_addr_plen <= net->back.ip6_addr_plen
			? &net->front.ip6_mask
			: &net->back.ip6_mask;
	return ip6_same_subnet(&net->front.ip6_addr, &net->back.ip6_addr,
		ip6_mask);
}

/* Initialize the network. */
int
gatekeeper_init_network(struct net_config *net_conf)
{
	int num_ports;
	int ret = -1;

	if (net_conf == NULL)
		return -1;

	if (net_conf->back_iface_enabled) {
		if (ipv4_if_configured(&net_conf->front) !=
				ipv4_if_configured(&net_conf->back)) {
			G_LOG(ERR, "net: front and back interfaces must either both support IPv4 or neither support IPv4\n");
			return -1;
		}
		if (ipv6_if_configured(&net_conf->front) !=
				ipv6_if_configured(&net_conf->back)) {
			G_LOG(ERR, "net: front and back interfaces must either both support IPv6 or neither support IPv6\n");
			return -1;
		}
		if (ipv4_if_configured(&net_conf->front) &&
				ipv4_if_configured(&net_conf->back) &&
				ipv4_test_same_subnet(net_conf)) {
			G_LOG(ERR, "net: the IPv4 addresses of the front and back interfaces cannot belong to the same subnet\n");
			return -1;
		}
		if (ipv6_if_configured(&net_conf->front) &&
				ipv6_if_configured(&net_conf->back) &&
				ipv6_test_same_subnet(net_conf)) {
			G_LOG(ERR, "net: the IPv6 addresses of the front and back interfaces cannot belong to the same subnet\n");
			return -1;
		}
	}

	net_conf->numa_nodes = find_num_numa_nodes();
	net_conf->numa_used = rte_calloc("numas", net_conf->numa_nodes,
		sizeof(*net_conf->numa_used), 0);
	if (net_conf->numa_used == NULL) {
		G_LOG(ERR, "net: %s: out of memory for NUMA used array\n",
			__func__);
		return -1;
	}

	/* Check port limits. */
	num_ports = net_conf->front.num_ports +
		(net_conf->back_iface_enabled ? net_conf->back.num_ports : 0);
	if (num_ports > rte_eth_dev_count_avail()) {
		G_LOG(ERR, "net: there are only %i network ports available to DPDK/Gatekeeper, but configuration is using %i ports\n",
			rte_eth_dev_count_avail(), num_ports);
		ret = -1;
		goto numa;
	}
	net_conf->front.total_pkt_burst = 0;
	net_conf->back.total_pkt_burst = 0;

	/* Initialize interfaces. */

	ret = launch_at_stage1(init_iface_stage1, &net_conf->front);
	if (ret < 0)
		goto numa;

	ret = launch_at_stage2(start_network_stage2, net_conf);
	if (ret < 0)
		goto destroy_front;

	if (net_conf->back_iface_enabled) {
		ret = launch_at_stage1(init_iface_stage1, &net_conf->back);
		if (ret < 0)
			goto do_not_start_net;
	}

	goto out;

do_not_start_net:
	pop_n_at_stage2(1);
destroy_front:
	pop_n_at_stage1(1);
numa:
	rte_free(net_conf->numa_used);
	net_conf->numa_used = NULL;
out:
	return ret;
}

void
gatekeeper_free_network(void)
{
	if (config.back_iface_enabled)
		destroy_iface(&config.back, IFACE_DESTROY_ALL);
	destroy_iface(&config.front, IFACE_DESTROY_ALL);
	rte_free(config.numa_used);
	config.numa_used = NULL;
}

int
net_launch_at_stage1(struct net_config *net,
	int front_rx_queues, int front_tx_queues,
	int back_rx_queues, int back_tx_queues,
	lcore_function_t *f, void *arg)
{
	int ret = launch_at_stage1(f, arg);

	if (ret < 0)
		return ret;

	RTE_VERIFY(front_rx_queues >= 0);
	RTE_VERIFY(front_tx_queues >= 0);
	net->front.num_rx_queues += front_rx_queues;
	net->front.num_tx_queues += front_tx_queues;

	if (net->back_iface_enabled) {
		RTE_VERIFY(back_rx_queues >= 0);
		RTE_VERIFY(back_tx_queues >= 0);
		net->back.num_rx_queues += back_rx_queues;
		net->back.num_tx_queues += back_tx_queues;
	}

	return 0;
}

bool
ipv4_configured(struct net_config *net_conf)
{
	if (net_conf->back_iface_enabled) {
		return ipv4_if_configured(&net_conf->front) &&
			ipv4_if_configured(&net_conf->back);
	}
	return ipv4_if_configured(&net_conf->front);
}

bool
ipv6_configured(struct net_config *net_conf)
{
	if (net_conf->back_iface_enabled) {
		return ipv6_if_configured(&net_conf->front) &&
			ipv6_if_configured(&net_conf->back);
	}
	return ipv6_if_configured(&net_conf->front);
}

void
send_pkts(uint8_t port, uint16_t tx_queue,
	uint16_t num_pkts, struct rte_mbuf **bufs)
{
	uint16_t i, num_tx_succ;

	if (num_pkts == 0)
		return;

	/* Send burst of TX packets, to second port of pair. */
	num_tx_succ = rte_eth_tx_burst(port, tx_queue, bufs, num_pkts);

	/* XXX #71 Do something better here! For now, free any unsent packets. */
	if (unlikely(num_tx_succ < num_pkts)) {
		for (i = num_tx_succ; i < num_pkts; i++)
			drop_packet(bufs[i]);
	}
}

/*
 * Optimized generic implementation of RSS hash function.
 * If you want the calculated hash value matches NIC RSS value,
 * you have to use special converted key with rte_convert_rss_key() fn.
 * @param input_tuple
 *   Pointer to input tuple with network order.
 * @param input_len
 *   Length of input_tuple in 4-bytes chunks.
 * @param *rss_key
 *   Pointer to RSS hash key.
 * @return
 *   Calculated hash value.
 */
static inline uint32_t
gk_softrss_be(const uint32_t *input_tuple, uint32_t input_len,
		const uint8_t *rss_key)
{
	uint32_t i;
	uint32_t j;
	uint32_t ret = 0;

	for (j = 0; j < input_len; j++) {
		/*
		 * Need to use little endian,
		 * since it takes ordering as little endian in both bytes and bits.
		 */
		uint32_t val = rte_be_to_cpu_32(input_tuple[j]);
		for (i = 0; i < 32; i++)
			if (val & (1 << (31 - i))) {
				/*
				 * The cast (uint64_t) is needed because when
				 * @i == 0, the expression requires a 32-bit
				 * shift of a 32-bit unsigned integer,
				 * what is undefined.
				 * The C standard only defines bit shifting
				 * up to the bit-size of the integer minus one.
				 * Finally, the cast (uint32_t) avoid promoting
				 * the expression before the bit-or (i.e. `|`)
				 * to uint64_t.
				 */
				ret ^= ((const uint32_t *)rss_key)[j] << i |
					(uint32_t)((uint64_t)
						(((const uint32_t *)rss_key)
							[j + 1])
						>> (32 - i));
			}
	}

	return ret;
}

uint32_t
rss_flow_hash(const struct gatekeeper_if *iface, const struct ip_flow *flow)
{
	if (flow->proto == RTE_ETHER_TYPE_IPV4) {
		RTE_BUILD_BUG_ON(sizeof(flow->f.v4) % sizeof(uint32_t) != 0);
		return gk_softrss_be((uint32_t *)&flow->f,
			(sizeof(flow->f.v4)/sizeof(uint32_t)),
			iface->rss_key_be);
	}

	if (likely(flow->proto == RTE_ETHER_TYPE_IPV6)) {
		RTE_BUILD_BUG_ON(sizeof(flow->f.v6) % sizeof(uint32_t) != 0);
		return gk_softrss_be((uint32_t *)&flow->f,
			(sizeof(flow->f.v6)/sizeof(uint32_t)),
			iface->rss_key_be);
	}

	rte_panic("%s(): unknown protocol: %i\n", __func__, flow->proto);
	return 0;
}
