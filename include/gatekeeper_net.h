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

#ifndef _GATEKEEPER_NET_H_
#define _GATEKEEPER_NET_H_

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/capability.h>

#include <rte_acl.h>
#include <rte_eth_bond.h>
#include <rte_ethdev.h>
#include <rte_timer.h>
#include <rte_ether.h>

#include "gatekeeper_flow.h"

/* To mark whether Gatekeeper/Grantor server configures IPv4 or IPv6. */
#define CONFIGURED_IPV4 (1)
#define CONFIGURED_IPV6 (2)

#define IPv6_DEFAULT_VTC_FLOW (0x60000000)

#define MAX_INET_ADDRSTRLEN (INET6_ADDRSTRLEN)

struct ipaddr {
	/* The network layer protocol of the nexthop. */
	uint16_t proto;

	/* The IP address of the nexthop. */
	union {
		struct in_addr  v4;
		struct in6_addr v6;
	} ip;
};

/*
 * The minimum and maximum sizes of the (secret) RSS hash key.
 *
 * These constants MUST be multiples of 4 since functions such
 * rte_convert_rss_key() expects so.
 */
#define GATEKEEPER_RSS_MIN_KEY_LEN (40)
#define GATEKEEPER_RSS_MAX_KEY_LEN (128)

/*
 * The maximum number of "rte_eth_rss_reta_entry64" structures can be used to
 * configure the Redirection Table of the Receive Side Scaling (RSS) feature.
 * Notice, each "rte_eth_rss_reta_entry64" structure can configure 64 entries 
 * of the table. To configure more than 64 entries supported by hardware,
 * an array of this structure is needed.
 */
#define GATEKEEPER_RETA_MAX_SIZE (ETH_RSS_RETA_SIZE_512 / RTE_RETA_GROUP_SIZE)

struct gatekeeper_rss_config {
	uint16_t reta_size;
	struct rte_eth_rss_reta_entry64 reta_conf[GATEKEEPER_RETA_MAX_SIZE];
};

/* Maximum number of ACL classification types. */
#define GATEKEEPER_ACL_MAX (16)

/*
 * Some blocks can receive packets via different
 * methods, such as via the NIC or mailboxes. These
 * methods can change depending on hardware support.
 */
enum {
	/* Receive packets from a NIC. */
	RX_METHOD_NIC = 0x1,

	/*
	 * Receive packets from a mailbox.
	 *
	 * Note: All packets that are matched through
	 * an ACL are delivered through mailboxes to
	 * the block that processes them.
	 */
	RX_METHOD_MB = 0x2
};

/*
 * Format of function called when a rule matches in the IPv6 ACL.
 * Need forward declaration because acl_cb_func and struct gatekeeper_if
 * are circularly defined.
 */
struct gatekeeper_if *iface;
typedef int (*acl_cb_func)(struct rte_mbuf **pkts, unsigned int num_pkts,
	struct gatekeeper_if *iface);
/* Format of function called when no rule matches in the IPv6 ACL. */
typedef int (*ext_cb_func)(struct rte_mbuf *pkt, struct gatekeeper_if *iface);

struct acl_state {
	/* Per-socket ACLs used for classifying packets. */
	struct rte_acl_ctx *acls[RTE_MAX_NUMA_NODES];

	/*
	 * Callback functions for each ACL rule type.
	 *
	 * On error, these functions should return a negative value
	 * and free all packets that have not already been handled.
	 */
	acl_cb_func        funcs[GATEKEEPER_ACL_MAX];

	/*
	 * Callback functions for each ACL rule type with
	 * extension headers.
	 *
	 * Returning values: 0 means a match and a negative value
	 * means an error or that there was no match.
	 */
	ext_cb_func        ext_funcs[GATEKEEPER_ACL_MAX];

	/* Number of ACL types installed in @funcs. */
	unsigned int       func_count;

	/*
	 * Whether this ACL is enabled.
	 *
	 * Set to true by ipv{4,6}_pkt_filter_add() when an ACL is
	 * determined to be needed.
	 */
	bool               enabled;
};

/*
 * A Gatekeeper interface is specified by a set of PCI addresses
 * that map to DPDK port numbers. If multiple ports are specified,
 * then the ports are bonded.
 */
struct gatekeeper_if {
	/* The ports (in PCI address format) that compose this interface. */
	char            **pci_addrs;

	/* The number of ports that in this interface (length of @pci_addrs). */
	uint8_t         num_ports;

	/* Name of the interface. Needed for setting/getting bonded port. */
	char            *name;

	/* Number of RX and TX queues for this interface. */
	uint16_t        num_rx_queues;
	uint16_t        num_tx_queues;

	/*
	 * The total burst size of any functional block that
	 * does not have hardware support for this interface.
	 */
	uint16_t        total_pkt_burst;

	/* Timeouts for cache entries (in seconds) for Link Layer Support. */
	uint32_t	arp_cache_timeout_sec;
	uint32_t	nd_cache_timeout_sec;

	/* The type of bonding used for this interface, if needed. */
	uint32_t        bonding_mode;

	/*
	 * Whether @ipv4_vlan_tag/@ipv6_vlan_tag should be applied to egress
	 * traffic.
	 */
	int             vlan_insert;

	/*
	 * Maximum permitted length of packets sent from and received on
	 * this interface. It is used to configure both the MTU of the
	 * device and the maximum RX packet length offload feature.
	 *
	 * Notes:
	 *
	 * The value here must conform to DPDK's limits (typically
	 * 64-16128 bytes) and also to whatever limits are imposed by
	 * the specific NIC being used.
	 *
	 * Before adjusting this value, you should take into account
	 * the hardware capabilities and the configured mbuf segment size
	 * in Gatekeeper. By default, the mbuf segment size and MTU are
	 * both set to 2048.
	 *
	 * Gatekeeper servers do not fragment packets on the back interface.
	 * If the back network does not support frame sizes sent by Gatekeeper,
	 * the packet will be dropped. For example, if Gatekeeper receives
	 * a frame close to 1500 bytes and encapsulates it (resulting in a
	 * frame above 1500 bytes), then the back interface may be able to
	 * transmit it but the network may drop it.
	 */
	uint16_t        mtu;

	/* The maximum packet lifetime. */
	uint8_t         ipv6_default_hop_limits;

	/*
	 * According to the 82599 datasheet, a receive descriptor is
	 * a data structure that contains the receive data buffer address
	 * and fields for hardware to store packet information. Upon receipt
	 * of a packet for this device, hardware stores the packet data into
	 * the indicated buffer and writes the length, status and errors to
	 * the receive descriptor.
	 *
	 * Each packet buffer is indicated by a descriptor.
	 */
	uint16_t        num_rx_desc;
	/*
	 * Similar to the receive descriptor, each packet buffer is
	 * indicated by a descriptor as well.
	 */
	uint16_t        num_tx_desc;

	/*
	 * Whether IPv4 UDP checksums should be enabled in hardware.
	 * Technically, this only affects the front interface, since
	 * only the GT block (on Grantor servers) uses UDP checksums.
	 */
	bool            ipv4_hw_udp_cksum;

	/*
	 * Whether IPv6 UDP checksums should be enabled in hardware.
	 * Technically, this only affects the front interface, since
	 * only the GT block (on Grantor servers) uses UDP checksums.
	 */
	bool            ipv6_hw_udp_cksum;

	/* Whether IPv4 (L3) checksums should be enabled in hardware. */
	bool		ipv4_hw_cksum;

	/*
	 * This field decides if the flag GRND_RANDOM is passed to getradom(2)
	 * while initializing field @rss_key.
	 */
	bool            guarantee_random_entropy;

	/*
	 * Some NICs do not support the RSS hash functions
	 * ETH_RSS_IPV4 amd ETH_RSS_IPV6 (i.e. RSS hash for IPv4 or IPv6
	 * non-fragmented packets).  But they may support the hash functions
	 * ETH_RSS_NONFRAG_IPV4_TCP, ETH_RSS_NONFRAG_IPV4_UDP,
	 * ETH_RSS_NONFRAG_IPV6_TCP, and ETH_RSS_NONFRAG_IPV6_UDP, and
	 * setting the input set of the hash these hash functions.
	 * An example of this behavior is the PMD i40e.
	 *
	 * Enabling the parameter below, Gatekeeper will try the alternative
	 * RSS hash.
	 *
	 * Currently, this parameter only works for PMD i40e.
	 *
	 * If the interface is bonded, all ports in the bond must either
	 * need this parameter disabled or enabled.
	 */
	bool            alternative_rss_hash;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */

	/* Link layer header length for egress packets from this interface. */
	size_t          l2_len_out;

	/* VLAN tag to be applied to all outbound IPv4 packets, in network order. */
	uint16_t        ipv4_vlan_tag_be;

	/* VLAN tag to be applied to all outbound IPv6 packets, in network order. */
	uint16_t        ipv6_vlan_tag_be;

	/* Ethernet address of this interface. */
	struct rte_ether_addr eth_addr;

	/* DPDK port IDs corresponding to each address in @pci_addrs. */
	uint16_t        *ports;

	/*
	 * The DPDK port ID for this interface.
	 *
	 * If @ports only has one element, then @id is that port.
	 * If @ports has multiple elements, then @id is the DPDK
	 * *bonded* port ID representing all of those ports.
	 */
	uint8_t         id;

	/* The RX and TX queue assignments on this interface for each lcore. */
	int16_t         rx_queues[RTE_MAX_LCORE];
	int16_t         tx_queues[RTE_MAX_LCORE];

	/*
	 * The next RX and TX queues to be assigned on this interface.
	 * We need atomic here in case multiple blocks are trying to
	 * configure their queues on the same interface at the same time.
	 */
	rte_atomic16_t  rx_queue_id;
	rte_atomic16_t  tx_queue_id;

	/*
	 * Specify the IPv4 and IPv6 addresses of this interface.
	 * Notice that, while one address must always be there,
	 * there may not be the second address.
	 */
	uint8_t         configured_proto;

	/* IPv4 address and network mask. */
	struct in_addr  ip4_addr;
	struct in_addr  ip4_mask;
	uint8_t         ip4_addr_plen;

	/*
	 * Global IPv6 address and network mask.
	 *
	 * This is the address/mask given by configuration
	 * and used for global routing.
	 */
	struct in6_addr ip6_addr;
	struct in6_addr ip6_mask;
	uint8_t         ip6_addr_plen;

	/*
	 * Addresses related to Neighbor Discovery.
	 */

	/*
	 * Link-local IPv6 address and network mask.
	 *
	 * ND messages can be sent from, and to, link-local IPv6
	 * addresses that are only routable inside the local
	 * network. We are also responsible for responding to
	 * resolution requests for the link-local address. It is
	 * automatically generated.
	 */
	struct in6_addr ll_ip6_addr;
	struct in6_addr ll_ip6_mask;

	/*
	 * IPv6 solicited-node multicast addresses.
	 *
	 * If a resolution is unknown, an ND Solicitation is sent
	 * to a solicited-node multicast address to reduce the
	 * number of hosts in the broadcast domain that receive
	 * the Solicitation. Two of these multicast addresses are
	 * automatically generated: one that covers the global IPv6
	 * address and one that covers the IPv6 link-local address.
	 */
	struct in6_addr ip6_mc_addr;
	struct in6_addr ll_ip6_mc_addr;

	/*
	 * IPv6 multicast Ethernet addresses.
	 *
	 * For packets that use a solicited-node multicast address
	 * for the IPv6 destination field, the Ethernet destination
	 * field should also use a special IPv6 multicast address.
	 * Two such addresses are automatically generated: they cover
	 * the global and link-local solicited-node multicast addresses.
	 */
	struct rte_ether_addr eth_mc_addr;
	struct rte_ether_addr ll_eth_mc_addr;

	/* Timer to transmit from LLS block to fulfill LACP TX requirement. */
	struct rte_timer  lacp_timer;

	/* ACLs and associated callback functions for matching packets. */
	struct acl_state  ipv4_acls;
	struct acl_state  ipv6_acls;

	/* Whether this interface supports RSS. */
	bool              rss;

	/* Whether the interface has been initialized. */
	bool              alive;

	/* Length of the RSS key in bytes. */
	uint8_t           rss_key_len;

	/*
	 * RSS hash key.
	 *
	 * The secret key of the RSS hash (RSK) must be random in order
	 * to prevent hackers from knowing it.
	 */
	uint8_t           rss_key[GATEKEEPER_RSS_MAX_KEY_LEN];
	/* @rss_key ready for use with rte_softrss_be(). */
	uint8_t           rss_key_be[GATEKEEPER_RSS_MAX_KEY_LEN];
};

uint32_t rss_flow_hash(const struct gatekeeper_if *iface,
	const struct ip_flow *flow);

/*
 * The atomic counters for @rx_queue_id and @tx_queue_id are
 * signed, so we get about 2^15 possible queues available for use,
 * which is much more than is needed.
 *
 * Use this constant as an out-of-band value to represent that
 * a queue has not been allocated; if one of the atomic counters
 * reaches this value, we have exceeded the number of possible
 * queues.
 */
#define GATEKEEPER_QUEUE_UNALLOCATED	(INT16_MIN)

enum queue_type {
	QUEUE_TYPE_RX,
	QUEUE_TYPE_TX,
	QUEUE_TYPE_MAX,
};

int get_queue_id(struct gatekeeper_if *iface, enum queue_type ty,
	unsigned int lcore, struct rte_mempool *mp);

/* Configuration for the Network. */
struct net_config {
	/*
	 * Set to zero (false) when a back interface is
	 * not needed, such as when running gatekeeper
	 * for Grantor.
	 */
	int                  back_iface_enabled;

	/*
	 * Number of attempts to wait for Gatekeeper links to
	 * come up during initialization.
	 */
	unsigned int         num_attempts_link_get;

	/*
	 * The NUMA nodes used in the host. Element i is true
	 * if NUMA node i is being used; otherwise it is false.
	 */
	bool                 *numa_used;

	/* Log level for all non-block related activity. */
	uint32_t             log_level;

	/* How often the log file should be rotated. The unit is second. */
	uint32_t             rotate_log_interval_sec;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */

	struct gatekeeper_if front;
	struct gatekeeper_if back;

	/* The total number of NUMA nodes in the host. */
	uint32_t             numa_nodes;

	/* The ID of the user that will run Gatekeeper after it boots. */
	uid_t                pw_uid;

	/* The group ID of the user that will run Gatekeeper after it boots. */
	gid_t                pw_gid;
};

/*
 * Initializes an array of 16 bytes that represents the IPv6 solicited
 * node multicast address. Users of this macro need to pass the IPv6
 * address as an array of 16 bytes, the last three of which are used
 * as the last three bytes of the multicast address as well.
 */
#define IPV6_SN_MC_ADDR(ipv6) {				\
		0xFF, 0x02, 0x00, 0x00,			\
		0x00, 0x00, 0x00, 0x00,			\
		0x00, 0x00, 0x00, 0x01,			\
		0xFF, ipv6[13], ipv6[14], ipv6[15],	\
	}

/* Call lacp_enabled() instead this function wherever possible. */
static inline int
__lacp_enabled(struct gatekeeper_if *iface)
{
	return	iface->bonding_mode == BONDING_MODE_8023AD;
}

static inline int
lacp_enabled(struct net_config *net, struct gatekeeper_if *iface)
{
	/* When @iface is the back, need to make sure it's enabled. */
	if (iface == &net->back)
		return net->back_iface_enabled && __lacp_enabled(iface);

	/* @iface is the front interface. */
	return __lacp_enabled(iface);
}

int lua_init_iface(struct gatekeeper_if *iface, const char *iface_name,
	const char **pci_addrs, uint8_t num_pci_addrs, const char **ip_cidrs,
	uint8_t num_ip_cidrs, uint16_t ipv4_vlan_tag, uint16_t ipv6_vlan_tag);

int get_ip_type(const char *ip_addr);
int convert_str_to_ip(const char *ip_addr, struct ipaddr *res);
int convert_ip_to_str(const struct ipaddr *ip_addr, char *res, int n);
int ethertype_flow_add(struct gatekeeper_if *iface, uint16_t ether_type,
	uint16_t queue_id);

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
 */
int ipv4_pkt_filter_add(struct gatekeeper_if *iface, rte_be32_t dst_ip_be,
	rte_be16_t src_port_be, rte_be16_t src_port_mask_be,
	rte_be16_t dst_port_be, rte_be16_t dst_port_mask_be,
	uint8_t proto, uint16_t queue_id,
	acl_cb_func cb_f, ext_cb_func ext_cb_f,
	uint8_t *rx_method);

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
 */
int ipv6_pkt_filter_add(struct gatekeeper_if *iface,
	const rte_be32_t *dst_ip_be_ptr32,
	rte_be16_t src_port_be, rte_be16_t src_port_mask_be,
	rte_be16_t dst_port_be, rte_be16_t dst_port_mask_be,
	uint8_t proto, uint16_t queue_id,
	acl_cb_func cb_f, ext_cb_func ext_cb_f,
	uint8_t *rx_method);

/*
 * Drop all Linux capabilities (capabilities(7))
 * except for those needed by a block.
 *
 * @caps contains the @ncap number of entries that
 * the block wants to keep.
 */
int needed_caps(int ncap, const cap_value_t *caps);

struct net_config *get_net_conf(void);
struct gatekeeper_if *get_if_front(struct net_config *net_conf);
struct gatekeeper_if *get_if_back(struct net_config *net_conf);
int gatekeeper_setup_rss(uint16_t port_id, uint16_t *queues,
	uint16_t num_queues);
int gatekeeper_get_rss_config(uint16_t port_id,
	struct gatekeeper_rss_config *rss_conf);
int gatekeeper_setup_user(struct net_config *net_conf,
	const char *user);
int gatekeeper_init_network(struct net_config *net_conf);
void gatekeeper_free_network(void);
bool ipv4_configured(struct net_config *net_conf);
bool ipv6_configured(struct net_config *net_conf);
unsigned int calculate_mempool_config_para(const char *block_name,
	struct net_config *net_conf, unsigned int total_pkt_burst);
struct rte_mempool *create_pktmbuf_pool(const char *block_name,
	unsigned int lcore, unsigned int num_mbuf);

/*
 * No cleanup for this step, since DPDK
 * doesn't offer a way to deallocate pools.
 */
static inline void
destroy_mempool(__attribute__((unused)) struct rte_mempool *mp)
{
	return;
}

static inline bool
ipv4_if_configured(const struct gatekeeper_if *iface)
{
	return !!(iface->configured_proto & CONFIGURED_IPV4);
}

static inline bool
ipv6_if_configured(const struct gatekeeper_if *iface)
{
	return !!(iface->configured_proto & CONFIGURED_IPV6);
}

/*
 * Compute the IPv4 checksum, either in hardware or software, depending
 * on the capabilities of the NIC and the configuration.
 *
 * The pkt->l2_len and pkt->l3_len must be set before calling this function,
 * although this is strictly only needed for hardware checksums.
 */
static inline void
set_ipv4_checksum(struct gatekeeper_if *iface, struct rte_mbuf *pkt,
	struct rte_ipv4_hdr *ipv4)
{
	/*
	 * The IP header checksum field must be set to 0 before
	 * computing the checksum (in hardware or software).
	 */
	ipv4->hdr_checksum = 0;
	pkt->ol_flags |= PKT_TX_IPV4;
	if (likely(iface->ipv4_hw_cksum))
		pkt->ol_flags |=  PKT_TX_IP_CKSUM;
	else
		ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);
}

static inline int
max_prefix_len(int ip_type)
{
	RTE_VERIFY(ip_type == AF_INET || ip_type == AF_INET6);
	return ip_type == AF_INET
		? sizeof(struct in_addr) * 8
		: sizeof(struct in6_addr) * 8;
}

static inline void
ip4_prefix_mask(uint8_t prefix_len, struct in_addr *ip4_mask)
{
	RTE_VERIFY(prefix_len <= 32 && ip4_mask != NULL);

	/*
	 * Need to be careful in case @prefix_len == 0,
	 * since in that case we will be shifting by 32
	 * bits, which is undefined for a 32-bit quantity.
	 * So shift using a 0ULL (at least 64 bits), and then
	 * cast back down to a 32-bit unsigned integer
	 * implicitly using rte_cpu_to_be_32().
	 */
	ip4_mask->s_addr = rte_cpu_to_be_32(~0ULL << (32 - prefix_len));
}

static inline void
ip6_prefix_mask(uint8_t prefix_len, struct in6_addr *ip6_mask)
{
	uint64_t *paddr;

	RTE_VERIFY(prefix_len <= 128 && ip6_mask != NULL);

	/*
	 * No portable way to do the same trick as IPv4,
	 * so make @prefix_len == 0 into its own case.
	 * Then, the other two cases shift by at most 63 bits.
	 */
	paddr = (uint64_t *)ip6_mask->s6_addr;
	if (prefix_len == 0) {
		paddr[0] = 0ULL;
		paddr[1] = 0ULL;
	} else if (prefix_len <= 64) {
		paddr[0] = rte_cpu_to_be_64(~0ULL << (64 - prefix_len));
		paddr[1] = 0ULL;
	} else {
		paddr[0] = ~0ULL;
		paddr[1] = rte_cpu_to_be_64(~0ULL << (128 - prefix_len));
	}
}

static inline bool
ip4_same_subnet(uint32_t addr1, uint32_t addr2, uint32_t ip4_mask)
{
	return !((addr1 ^ addr2) & ip4_mask);
}

static inline bool
ip6_same_subnet(const struct in6_addr *addr1, const struct in6_addr *addr2,
	const struct in6_addr *ip6_mask)
{
	const uint64_t *paddr_p1 = (const uint64_t *)addr1;
	const uint64_t *paddr_p2 = (const uint64_t *)addr2;
	const uint64_t *pmask_p = (const uint64_t *)ip6_mask;
	return (!((paddr_p1[0] ^ paddr_p2[0]) & pmask_p[0]) &&
		!((paddr_p1[1] ^ paddr_p2[1]) & pmask_p[1]));
}

static inline int
drop_packet(struct rte_mbuf *pkt)
{
	rte_pktmbuf_free(pkt);
	return 0;
}

void send_pkts(uint8_t port, uint16_t tx_queue,
	uint16_t num_pkts, struct rte_mbuf **bufs);

/*
 * Postpone the execution of f(arg) until the Lua configuration finishes,
 * but before the network devices start.
 *
 * This initilization stage is perfect for allocation of queues in
 * the network devices.
 *
 * If you do not need to allocate any queue, you can may call
 * net_launch_at_stage1() instead.
 *
 * front_rx_queues, front_tx_queues, back_rx_queues, and back_tx_queues are
 * the number of queues on the front and back interfaces of the receiving and
 * transmitting types.
 *
 * If the back interface is not enabled, the parameters back_rx_queues and
 * back_tx_queues are ignored.
 *
 * RETURN
 *	Return 0 if success; otherwise -1.
 */
int
net_launch_at_stage1(struct net_config *net,
	int front_rx_queues, int front_tx_queues,
	int back_rx_queues, int back_tx_queues,
	lcore_function_t *f, void *arg);

/*
 * Do any processing necessary to end stage 2 -- the last part of the
 * network configuration that happens before individual lcores are
 * launched. This is useful for any network configuration that requires
 * input from the individual blocks in stage 2.
 */
int finalize_stage2(void *arg);

#endif /* _GATEKEEPER_NET_H_ */
