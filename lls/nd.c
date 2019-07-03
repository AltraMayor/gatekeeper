/*
 * Gatekeeper - DoS protection system.
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

#include <arpa/inet.h>
#include <stdbool.h>

#include <rte_ip.h>

#include "gatekeeper_varip.h"
#include "cache.h"
#include "nd.h"

/*
 * Neighbor Discovery.
 *
 * This is an implementation of ND as defined in RFC 4861:
 *   https://tools.ietf.org/html/rfc4861
 *
 * However, Gatekeeper ND is only currently used for address
 * resolution, for both our global or link-local IPv6 address.
 * We do not handle any router or redirection messages.
 *
 * Only supporting address resolution has consequences. These
 * include but are not limited to:
 *
 *   - We do not implement Duplicate Address Detection, although
 *     we operate normally when we receive ND packets from hosts
 *     who may be trying to participate in DAD and transmit with
 *     an unspecified IPv6 source address.
 *   - We do not use the Router flag in our own ND advertisements,
 *     although we do not fail when we receive ND advertisements
 *     with any particular setting of the Router flag.
 *   - We do not support any ND header options EXCEPT for Source
 *     Link-Layer Address and Target Link-layer Address, although
 *     we do not fail when we receive an ND packet with a different
 *     option.
 *   - We do not maintain a neighbor cache as specified by RFC 4861,
 *     which specifies various states (STALE, INCOMPLETE, REACHABLE)
 *     for neighbor cache entries.
 */

/*
 * Returns whether a given IPv6 address is the unspecified address,
 * which can be used for duplicate address detection.
 */
static inline int
ipv6_addr_unspecified(const uint8_t *ip6_addr)
{
	const uint64_t *paddr = (const uint64_t *)ip6_addr;
	return (paddr[0] | paddr[1]) == 0ULL;
}

/*
 * Returns whether a given IPv6 address is a solicited-node
 * multicast address.
 */
static inline int
ipv6_addr_solicited_node_mc(const uint8_t *ip6_addr)
{
	const uint64_t *paddr = (const uint64_t *)ip6_addr;
	return ((paddr[0] ^ rte_cpu_to_be_64(0xff02000000000000UL)) |
		((paddr[1] ^ rte_cpu_to_be_64(0x00000001ff000000UL)) &
		rte_cpu_to_be_64(0xffffffffff000000UL))) == 0ULL;
}

/* Returns whether a given IPv6 address is generally a multicast address. */
static inline int
ipv6_addr_multicast(const uint8_t *ip6_addr)
{
	return ((*(const uint32_t *)ip6_addr) & rte_cpu_to_be_32(0xFF000000)) ==
		rte_cpu_to_be_32(0xFF000000);
}

int
iface_nd_enabled(struct net_config *net, struct gatekeeper_if *iface)
{
	/* When @iface is the back, need to make sure it's enabled. */
	if (iface == &net->back)
		return net->back_iface_enabled && ipv6_if_configured(iface);

	/* @iface is the front interface. */
	return ipv6_if_configured(iface);
}

int
ipv6_in_subnet(struct gatekeeper_if *iface, const struct ipaddr *addr)
{
	/* Check for both link-local and global subnets. */
	return (ip6_same_subnet(&iface->ll_ip6_addr, &addr->ip.v6,
		&iface->ll_ip6_mask)
		||
		ip6_same_subnet(&iface->ip6_addr, &addr->ip.v6,
		&iface->ip6_mask));
}

/*
 * RFC 4861, Section 7.2.2: Sending Neighbor Solicitations.
 *
 * We do not follow the requirement from the RFC to retain a small
 * queue of packets waiting for resolution. It states that this
 * queue is required, but also says that packets can be dropped from
 * this queue due to overflow.
 *
 * Therefore, the expectation is that retransmissions due to resolution
 * may need to happen, so we do not maintain this queue at all and expect
 * any interested clients will have already called hold_nd() anyway.
 *
 * Also, we do not stop trying to resolve an address while there are
 * holds on the entry, and do not return ICMPv6 destination unreachable
 * indications as required by the RFC.
 */
void
xmit_nd_req(struct gatekeeper_if *iface, const struct ipaddr *addr,
	const struct rte_ether_addr *ha, uint16_t tx_queue)
{
	struct lls_config *lls_conf = get_lls_conf();
	const uint8_t *ipv6_addr = addr->ip.v6.s6_addr;

	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct icmpv6_hdr *icmpv6_hdr;
	struct nd_neigh_msg *nd_msg;
	struct nd_opt_lladdr *nd_opt;
	size_t l2_len;

	struct rte_mempool *mp = lls_conf->net->gatekeeper_pktmbuf_pool[
		rte_lcore_to_socket_id(lls_conf->lcore_id)];
	struct rte_mbuf *created_pkt = rte_pktmbuf_alloc(mp);
	if (created_pkt == NULL) {
		LLS_LOG(ERR,
			"Could not alloc a packet for an ND Neighbor Solicitation\n");
		return;
	}

	/* Solicitation will include source link layer address. */
	l2_len = iface->l2_len_out;
	created_pkt->data_len = ND_NEIGH_PKT_LLADDR_MIN_LEN(l2_len);
	created_pkt->pkt_len = created_pkt->data_len;

	/* Set-up Ethernet header. */
	eth_hdr = rte_pktmbuf_mtod(created_pkt, struct rte_ether_hdr *);
	rte_ether_addr_copy(&iface->eth_addr, &eth_hdr->s_addr);
	if (ha == NULL) {
		/*
		 * Need to use IPv6 multicast Ethernet address.
		 * Technically, the last four bytes of this
		 * address should be the same as the solicited-node
		 * multicast address formed using @ipv6_addr, but
		 * this is equivalent to 0xFF followed by the
		 * last three bytes of @ipv6_addr.
		 */
		struct rte_ether_addr eth_mc_daddr = { {
			0x33, 0x33, 0xFF,
			ipv6_addr[13], ipv6_addr[14], ipv6_addr[15],
		} };
		rte_ether_addr_copy(&eth_mc_daddr, &eth_hdr->d_addr);
	} else
		rte_ether_addr_copy(ha, &eth_hdr->d_addr);

	/* Set-up VLAN header. */
	if (iface->vlan_insert)
		fill_vlan_hdr(eth_hdr, iface->vlan_tag_be, RTE_ETHER_TYPE_IPV6);
	else
		eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

	/* Set-up IPv6 header. */
	ipv6_hdr = pkt_out_skip_l2(iface, eth_hdr);
	ipv6_hdr->vtc_flow = rte_cpu_to_be_32(IPv6_DEFAULT_VTC_FLOW);
	ipv6_hdr->payload_len = rte_cpu_to_be_16(created_pkt->data_len -
		(l2_len + sizeof(*ipv6_hdr)));
	ipv6_hdr->proto = IPPROTO_ICMPV6;
	/*
	 * The IP Hop Limit field must be 255 as required by
	 * RFC 4861, sections 7.1.1 and 7.1.2.
	 */
	ipv6_hdr->hop_limits = 255;
	rte_memcpy(ipv6_hdr->src_addr, iface->ll_ip6_addr.s6_addr,
		sizeof(ipv6_hdr->src_addr));

	if (ha == NULL) {
		/* Need to use IPv6 solicited-node multicast address. */
		uint8_t ip6_mc_daddr[16] = IPV6_SN_MC_ADDR(ipv6_addr);
		rte_memcpy(ipv6_hdr->dst_addr, ip6_mc_daddr,
			sizeof(ipv6_hdr->dst_addr));
	} else
		rte_memcpy(ipv6_hdr->dst_addr, ipv6_addr,
			sizeof(ipv6_hdr->dst_addr));

	/* Set-up ICMPv6 header. */
	icmpv6_hdr = (struct icmpv6_hdr *)&ipv6_hdr[1];
	icmpv6_hdr->type = ND_NEIGHBOR_SOLICITATION;
	icmpv6_hdr->code = 0;
	icmpv6_hdr->cksum = 0; /* Calculated below. */

	/* Set-up ND header with options. */
	nd_msg = (struct nd_neigh_msg *)&icmpv6_hdr[1];
	nd_msg->flags = 0;
	rte_memcpy(nd_msg->target, ipv6_addr, sizeof(nd_msg->target));
	nd_opt = (struct nd_opt_lladdr *)&nd_msg[1];
	nd_opt->type = ND_OPT_SOURCE_LL_ADDR;
	nd_opt->len = 1;
	rte_ether_addr_copy(&iface->eth_addr, &nd_opt->ha);

	icmpv6_hdr->cksum = rte_ipv6_icmpv6_cksum(ipv6_hdr, icmpv6_hdr);

	if (rte_eth_tx_burst(iface->id, tx_queue, &created_pkt, 1) <= 0) {
		rte_pktmbuf_free(created_pkt);
		LLS_LOG(ERR, "Could not send an ND Neighbor Solicitation\n");
	}
}

/*
 * Parse the options of an ND packet, looking specifically for
 * ND_OPT_SOURCE_LL_ADDR (in Neighbor Solicitations) and
 * ND_OPT_TARGET_LL_ADDR (in Neighbor Advertisements).
 *
 * Returns NULL if there are partial options or if the length
 * field of any option is set to zero. Otherwise, returns the
 * given @ndopts structure which contains an array of pointers
 * to the relevant options.
 */
static struct nd_opts *
parse_nd_opts(struct nd_opts *ndopts, uint8_t *opt, uint16_t opt_len)
{
	struct nd_opt_hdr *nd_opt = (struct nd_opt_hdr *)opt;
	memset(ndopts, 0, sizeof(*ndopts));

	while (opt_len) {
		int len_bytes;

		if (opt_len < sizeof(*nd_opt))
			return NULL;

		/* @nd_opt->len is the number of 64-bit chunks. */
		len_bytes = nd_opt->len << 3;
		if (opt_len < len_bytes || len_bytes == 0)
			return NULL;

		switch (nd_opt->type) {
		case ND_OPT_SOURCE_LL_ADDR:
		case ND_OPT_TARGET_LL_ADDR:
			if (ndopts->opt_array[nd_opt->type])
				LLS_LOG(INFO, "Multiple options of type %d in an ND Neighbor packet\n",
					nd_opt->type);
			else
				ndopts->opt_array[nd_opt->type] = nd_opt;
			break;
		default:
			/*
			 * No support for Prefix Information, Redirected Header,
			 * MTU, Route Information, or any other ND option.
			 */
			break;
		}

		opt_len -= len_bytes;
		nd_opt = (struct nd_opt_hdr *)((uint8_t *)nd_opt + len_bytes);
	}

	return ndopts;
}

/*
 * RFC 4861, Section 7.2.3: Receipt of Neighbor Solicitations.
 *
 * If the newly-received source link-layer address differs from the
 * one already in the cache, we do not set the entry to stale as
 * required by the RFC.
 */
static int
process_nd_neigh_solicitation(struct lls_config *lls_conf, struct rte_mbuf *buf,
	struct rte_ether_hdr *eth_hdr, struct rte_ipv6_hdr *ipv6_hdr,
	struct icmpv6_hdr *icmpv6_hdr, uint16_t pkt_len, size_t l2_len,
	uint16_t icmpv6_len, struct gatekeeper_if *iface, uint16_t tx_queue)
{
	struct nd_neigh_msg *nd_msg = (struct nd_neigh_msg *)&icmpv6_hdr[1];
	struct nd_opt_lladdr *nd_opt;
	struct nd_opts ndopts;
	int src_unspec = ipv6_addr_unspecified(ipv6_hdr->src_addr);
	struct rte_ether_addr *src_eth_addr = NULL;
	size_t min_len;
	int ret;

	/*
	 * Most of the checks required by RFC 4861, Section 7.1.1
	 * have already been done by nd_pkt_valid().
	 */

	/*
	 * RFC 4861, Section 7.1.1.
	 *
	 * Target Address must not be a multicast address.
	 */
	if (ipv6_addr_multicast(nd_msg->target))
		return -1;

	/*
	 * RFC 4861, Section 7.1.1.
	 *
	 * If the IP source address is the unspecified address, the IP
	 * destination address must be a solicited-node multicast address.
	 */
	if (src_unspec && !ipv6_addr_solicited_node_mc(ipv6_hdr->dst_addr))
		return -1;

	/*
	 * RFC 4861, Section 7.2.3.
	 *
	 * The Target Address must be a "valid" unicast or anycast address
	 * assigned to the receiving interface. For us, this could be
	 * our global or link-local IPv6 address.
	 *
	 * We do not implement an ND proxy service or Duplicate Address
	 * Detection, so we don't need to check for the Target Address
	 * for those.
	 */
	if (!ipv6_addrs_equal(iface->ip6_addr.s6_addr, nd_msg->target) &&
			!ipv6_addrs_equal(iface->ll_ip6_addr.s6_addr,
			nd_msg->target))
		return -1;

	/* Process any ND neighbor options and save them in @ndopts. */
	if (parse_nd_opts(&ndopts, nd_msg->opts, icmpv6_len -
			(sizeof(*icmpv6_hdr) + sizeof(*nd_msg))) == NULL)
		return -1;

	if (ndopts.opt_array[ND_OPT_SOURCE_LL_ADDR] != NULL) {
		struct lls_mod_req mod_req = {
			.cache = &lls_conf->nd_cache,
			.addr.proto = RTE_ETHER_TYPE_IPV6,
			.port_id = iface->id,
			.ts = time(NULL),
		};

		/*
		 * RFC 4861, Section 7.1.1.
		 *
		 * If the source address is unspecified, there must
		 * not be the source link layer address option.
		 */
		if (src_unspec)
			return -1;

		RTE_VERIFY(mod_req.ts >= 0);
		nd_opt = (struct nd_opt_lladdr *)
			ndopts.opt_array[ND_OPT_SOURCE_LL_ADDR];

		/* Update resolution of source of Solicitation. */
		rte_memcpy(mod_req.addr.ip.v6.s6_addr, ipv6_hdr->src_addr,
			sizeof(mod_req.addr.ip.v6.s6_addr));
		rte_ether_addr_copy(&nd_opt->ha, &mod_req.ha);
		lls_process_mod(lls_conf, &mod_req);

		/* Save source address to use in advertisement. */
		src_eth_addr = &nd_opt->ha;
	} else {
		/*
		 * If source link layer address is not in the options,
		 * get the source resolution, if we have it.
		 */
		struct ipaddr addr = { .proto = RTE_ETHER_TYPE_IPV6 };
		rte_memcpy(addr.ip.v6.s6_addr, ipv6_hdr->src_addr,
			sizeof(addr.ip.v6.s6_addr));
		struct lls_map *map = lls_cache_get(&lls_conf->nd_cache,
			&addr);
		if (map != NULL)
			src_eth_addr = &map->ha;
	}

	/* Make sure buffer is correct size. */
	min_len = ND_NEIGH_PKT_LLADDR_MIN_LEN(l2_len);
	RTE_VERIFY(RTE_MBUF_DEFAULT_BUF_SIZE >= min_len);
	if (pkt_len > min_len) {
		if (rte_pktmbuf_trim(buf, pkt_len - min_len) < 0) {
			LLS_LOG(ERR, "Could not trim packet to correct size for response to a Neighbor Solicitation\n");
			return -1;
		}
	} else if (pkt_len < min_len) {
		if (rte_pktmbuf_append(buf, min_len - pkt_len) == NULL) {
			LLS_LOG(ERR, "Could not append space to packet to correct size for response to a Neighbor Solicitation\n");
			return -1;
		}
	}

	ret = verify_l2_hdr(iface, eth_hdr, buf->l2_type, "ND");
	if (ret < 0)
		return ret;

	if (src_eth_addr != NULL) {
		/*
		 * RFC 4861, Section 7.2.4:
		 * Sending Solicited Neighbor Advertisements.
		 *
		 * Since we re-use the buffer, we skip over
		 * any fields whose value should stay the
		 * same from the Neighbor Solicitation.
		 * Since the reply always goes out the same
		 * interface that received it, the L2 space
		 * of the packet is the same. If needed, the
		 * correct VLAN tag was set in verify_l2_hdr().
		 */

		/* Set-up Ethernet header. */
		rte_ether_addr_copy(&iface->eth_addr, &eth_hdr->s_addr);
		rte_ether_addr_copy(src_eth_addr, &eth_hdr->d_addr);

		/* Set-up IPv6 header. */
		nd_msg->flags = 0;
		ipv6_hdr->payload_len =
			rte_cpu_to_be_16(min_len -
				(l2_len + sizeof(*ipv6_hdr)));
		if (src_unspec) {
			struct in6_addr all_nodes_addr = {
				.s6_addr = {
					0xFF, 0x01, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x01,
				},
			};
			rte_memcpy(ipv6_hdr->dst_addr, all_nodes_addr.s6_addr,
				sizeof(ipv6_hdr->dst_addr));
		} else
			rte_memcpy(ipv6_hdr->dst_addr, ipv6_hdr->src_addr,
				sizeof(ipv6_hdr->dst_addr));
		/*
		 * This can be any address from our interface,
		 * but the Linux implementation seems to use
		 * whatever the target is (as long as we own
		 * that address), so we'll use it too.
		 */
		rte_memcpy(ipv6_hdr->src_addr, nd_msg->target,
			sizeof(ipv6_hdr->src_addr));

		/* Set-up ICMPv6 header. */
		icmpv6_hdr->type = ND_NEIGHBOR_ADVERTISEMENT;
		icmpv6_hdr->cksum = 0; /* Calculated below. */

		/* Set up ND Advertisement header with target LL addr option. */
		if (src_unspec)
			nd_msg->flags = rte_cpu_to_be_32(LLS_ND_NA_OVERRIDE);
		else
			nd_msg->flags = rte_cpu_to_be_32(
				LLS_ND_NA_OVERRIDE | LLS_ND_NA_SOLICITED);
		nd_opt = (struct nd_opt_lladdr *)&nd_msg[1];
		nd_opt->type = ND_OPT_TARGET_LL_ADDR;
		nd_opt->len = 1;
		rte_ether_addr_copy(&iface->eth_addr, &nd_opt->ha);

		icmpv6_hdr->cksum = rte_ipv6_icmpv6_cksum(ipv6_hdr, icmpv6_hdr);

		if (rte_eth_tx_burst(iface->id, tx_queue, &buf, 1) <= 0) {
			LLS_LOG(ERR, "Could not send an ND Neighbor Advertisement in response to a Solicitation\n");
			return -1;
		}
	} else {
		/*
		 * Can't respond to the original solicitation
		 * until we resolve the address of the source.
		 */

		/*
		 * RFC 4861, Section 7.2.2: Sending Neighbor Solicitations.
		 *
		 * Use the same approach as xmit_nd_req(), but don't use
		 * that function directly since we already have a buffer
		 * that has some of the fields correctly filled-in.
		 * Since the new solicitation always goes out the same
		 * interface that received the original, the L2 space
		 * of the packet is the same. If needed, the correct VLAN
		 * tag was set in verify_l2_hdr().
		 */

		uint8_t ip6_mc_daddr[16] = IPV6_SN_MC_ADDR(ipv6_hdr->src_addr);
		struct rte_ether_addr eth_mc_daddr = { {
			            0x33,             0x33,
			ip6_mc_daddr[12], ip6_mc_daddr[13],
			ip6_mc_daddr[14], ip6_mc_daddr[15],
		} };

		/*
		 * The RFC doesn't mention this case specificatlly,
		 * but if the source IP address was unspecified and
		 * we don't already have a resolution for it, we
		 * don't know where to send a solicitation.
		 */
		if (src_unspec)
			return -1;

		rte_ether_addr_copy(&iface->eth_addr, &eth_hdr->s_addr);
		rte_ether_addr_copy(&eth_mc_daddr, &eth_hdr->d_addr);

		/* Set-up IPv6 header. */
		ipv6_hdr->payload_len =
			rte_cpu_to_be_16(min_len -
				(l2_len + sizeof(*ipv6_hdr)));
		rte_memcpy(nd_msg->target, ipv6_hdr->src_addr,
			sizeof(nd_msg->target));
		rte_memcpy(ipv6_hdr->dst_addr, ip6_mc_daddr,
			sizeof(ipv6_hdr->dst_addr));
		rte_memcpy(ipv6_hdr->src_addr, iface->ll_ip6_addr.s6_addr,
			sizeof(ipv6_hdr->src_addr));

		/* Set-up ICMPv6 header. */
		icmpv6_hdr->cksum = 0; /* Calculated below. */

		/* Set up ND Solicitation header with source LL addr option. */
		nd_msg->flags = 0;
		nd_opt = (struct nd_opt_lladdr *)&nd_msg[1];
		nd_opt->type = ND_OPT_SOURCE_LL_ADDR;
		nd_opt->len = 1;
		rte_ether_addr_copy(&iface->eth_addr, &nd_opt->ha);

		icmpv6_hdr->cksum = rte_ipv6_icmpv6_cksum(ipv6_hdr, icmpv6_hdr);

		if (rte_eth_tx_burst(iface->id, tx_queue, &buf, 1) <= 0) {
			LLS_LOG(ERR, "Could not send an ND Neighbor Solicitation in response to a Solicitation\n");
			return -1;
		}
	}

	return 0;
}

/*
 * RFC 4861, Section 7.2.5: Receipt of Neighbor Advertisements.
 *
 * The RFC states that there is no need to create an entry if
 * none exists, but we do.
 *
 * We do not adhere to the meanings of the Router, Solicited,
 * or Override flags when it comes to updating an entry (although
 * we do use the Solicited flag in a validity test), because
 * we make no distinction between cache entry states such as
 * STALE, INCOMPLETE, and UNREACHABLE as described by the RFC.
 * We don't care about whether an entry is a router or whether an
 * announcement was solicited, we do not implement Neighbor
 * Unreachability Detection, and we always update an entry
 * even when the Override flag is not set.
 */
static int
process_nd_neigh_advertisement(struct lls_config *lls_conf,
	struct rte_ipv6_hdr *ipv6_hdr, struct icmpv6_hdr *icmpv6_hdr,
	uint16_t icmpv6_len, struct gatekeeper_if *iface)
{
	struct nd_neigh_msg *nd_msg = (struct nd_neigh_msg *)&icmpv6_hdr[1];
	struct nd_opt_lladdr *nd_opt;
	struct nd_opts ndopts;

	/*
	 * Most of the checks required by RFC 4861, Section 7.1.2
	 * have already been done by nd_pkt_valid().
	 */

	/*
	 * RFC 4861, Section 7.1.2.
	 *
	 * Target Address must not be a multicast address.
	 */
	if (ipv6_addr_multicast(nd_msg->target))
		return -1;

	/*
	 * RFC 4861, Section 7.1.2.
	 *
	 * If the IP Destination Address is a multicast address
	 * the Solicited flag must be zero.
	 */
	if (ipv6_addr_multicast(ipv6_hdr->dst_addr) &&
			(nd_msg->flags & rte_cpu_to_be_32(LLS_ND_NA_SOLICITED)))
		return -1;

	/* Process any ND neighbor options and save them in @ndopts. */
	if (parse_nd_opts(&ndopts, nd_msg->opts, icmpv6_len -
			(sizeof(*icmpv6_hdr) + sizeof(*nd_msg))) == NULL)
		return -1;

	if (ndopts.opt_array[ND_OPT_TARGET_LL_ADDR] != NULL) {
		struct lls_mod_req mod_req = {
			.cache = &lls_conf->nd_cache,
			.addr.proto = RTE_ETHER_TYPE_IPV6,
			.port_id = iface->id,
			.ts = time(NULL),
		};

		RTE_VERIFY(mod_req.ts >= 0);
		nd_opt = (struct nd_opt_lladdr *)
			ndopts.opt_array[ND_OPT_TARGET_LL_ADDR];

		rte_memcpy(mod_req.addr.ip.v6.s6_addr, nd_msg->target,
			sizeof(mod_req.addr.ip.v6.s6_addr));
		rte_ether_addr_copy(&nd_opt->ha, &mod_req.ha);
		lls_process_mod(lls_conf, &mod_req);
	}

	/* Always need to free the packet. */
	return -1;
}

/*
 * Perform sanity checks to make sure this is a valid ND neighbor packet.
 * By RFC 4861, sections 7.1.1 and 7.1.2, these checks are required for both
 * Solicitations and Advertisements.
 */
static int
nd_pkt_valid(struct rte_ipv6_hdr *ipv6_hdr, struct icmpv6_hdr *icmpv6_hdr,
	uint16_t icmpv6_len)
{
	return ipv6_hdr->hop_limits == 255 &&
		rte_be_to_cpu_16(ipv6_hdr->payload_len) == icmpv6_len &&
		icmpv6_hdr->code == 0 &&
		rte_ipv6_icmpv6_cksum(ipv6_hdr, icmpv6_hdr) == 0xFFFF;
}

int
process_nd(struct lls_config *lls_conf, struct gatekeeper_if *iface,
	struct rte_mbuf *buf)
{
	/*
	 * The ICMPv6 header offset in terms of the
	 * beginning of the IPv6 header.
	 */
	int icmpv6_offset;
	uint8_t nexthdr;

	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct icmpv6_hdr *icmpv6_hdr;

	uint16_t tx_queue = iface == &lls_conf->net->front
		? lls_conf->tx_queue_front
		: lls_conf->tx_queue_back;
	uint16_t pkt_len;
	size_t l2_len;
	uint16_t icmpv6_len;

	if (unlikely(!ipv6_if_configured(iface)))
		return -1;

	/* pkt_in_skip_l2() was already called by GK or GT. */
	l2_len = pkt_in_l2_hdr_len(buf);
	pkt_len = rte_pktmbuf_data_len(buf);
	if (pkt_len < ND_NEIGH_PKT_MIN_LEN(l2_len)) {
		LLS_LOG(NOTICE, "ND packet received is %"PRIx16" bytes but should be at least %lu bytes in %s\n",
			pkt_len, ND_NEIGH_PKT_MIN_LEN(l2_len), __func__);
		return -1;
	}

	ipv6_hdr = rte_pktmbuf_mtod_offset(buf, struct rte_ipv6_hdr *, l2_len);
	icmpv6_offset = ipv6_skip_exthdr(ipv6_hdr, buf->data_len -
		l2_len, &nexthdr);
	if (icmpv6_offset < 0 || nexthdr != IPPROTO_ICMPV6)
		return -1;

	if (pkt_len < (ND_NEIGH_PKT_MIN_LEN(l2_len) +
			icmpv6_offset - sizeof(*ipv6_hdr))) {
		LLS_LOG(NOTICE, "ND packet received is %"PRIx16" bytes but should be at least %lu bytes in %s\n",
			pkt_len, ND_NEIGH_PKT_MIN_LEN(l2_len) +
			icmpv6_offset - sizeof(*ipv6_hdr), __func__);
		return -1;
	}

	icmpv6_hdr = (struct icmpv6_hdr *)
		((uint8_t *)ipv6_hdr + icmpv6_offset);
	icmpv6_len = pkt_len - (l2_len + icmpv6_offset);

	if (unlikely(!nd_pkt_valid(ipv6_hdr, icmpv6_hdr, icmpv6_len)))
		return -1;

	eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	switch (icmpv6_hdr->type) {
	case ND_NEIGHBOR_SOLICITATION:
		return process_nd_neigh_solicitation(lls_conf, buf, eth_hdr,
			ipv6_hdr, icmpv6_hdr, pkt_len, l2_len, icmpv6_len,
			iface, tx_queue);
	case ND_NEIGHBOR_ADVERTISEMENT:
		return process_nd_neigh_advertisement(lls_conf,
			ipv6_hdr, icmpv6_hdr, icmpv6_len, iface);
	default:
		LLS_LOG(NOTICE, "%s received an ICMPv6 packet that's not a Neighbor Solicitation or Neighbor Advertisement (%hhu)\n",
			__func__, icmpv6_hdr->type);
		return -1;
	}

	rte_panic("Reached the end of %s without hitting a switch case\n",
		__func__);
	return 0;
}
