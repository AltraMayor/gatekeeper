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

#include <stdbool.h>
#include <arpa/inet.h>

#include <rte_hash.h>
#include <rte_icmp.h>

#include <gatekeeper_cps.h>
#include <gatekeeper_lls.h>
#include "gatekeeper_varip.h"
#include "cache.h"
#include "arp.h"
#include "nd.h"

static void
lls_send_request(struct lls_config *lls_conf, struct lls_cache *cache,
	const struct ipaddr *addr, const struct rte_ether_addr *ha)
{
	struct gatekeeper_if *front = &lls_conf->net->front;
	struct gatekeeper_if *back = &lls_conf->net->back;
	if (cache->iface_enabled(lls_conf->net, front) &&
			cache->ip_in_subnet(front, addr))
		cache->xmit_req(&lls_conf->net->front, addr, ha,
			lls_conf->tx_queue_front);
	if (cache->iface_enabled(lls_conf->net, back) &&
			cache->ip_in_subnet(back, addr))
		cache->xmit_req(&lls_conf->net->back, addr, ha,
			lls_conf->tx_queue_back);
}

static void
lls_cache_dump(struct lls_cache *cache)
{
	uint32_t iter = 0;
	int32_t index;
	const void *key;
	void *data;

	LLS_LOG(DEBUG, "LLS cache (%s)\n=====================\n", cache->name);
	index = rte_hash_iterate(cache->hash, &key, &data, &iter);
	while (index >= 0) {
		struct lls_record *record = &cache->records[index];
		struct lls_map *map = &record->map;
		char ip_str[MAX_INET_ADDRSTRLEN];
		int ret = convert_ip_to_str(&map->addr, ip_str,
			sizeof(ip_str));
		if (unlikely(ret < 0)) {
			LLS_LOG(DEBUG, "Couldn't convert cache record's IP address to string\n");
			goto next;
		}

		if (map->stale) {
			LLS_LOG(DEBUG, "%s: unresolved (%u holds)\n",
				ip_str, record->num_holds);
		} else {
			LLS_LOG(DEBUG,
				"%s: %02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8" (port %hhu) (%u holds)\n",
				ip_str,
				map->ha.addr_bytes[0], map->ha.addr_bytes[1],
				map->ha.addr_bytes[2], map->ha.addr_bytes[3],
				map->ha.addr_bytes[4], map->ha.addr_bytes[5],
				map->port_id, record->num_holds);
		}
next:
		index = rte_hash_iterate(cache->hash, &key, &data, &iter);
	}
}

static void
lls_update_subscribers(struct lls_record *record)
{
	unsigned int i;
	for (i = 0; i < record->num_holds; i++) {
		int call_again = false;

		record->holds[i].cb(&record->map, record->holds[i].arg,
			LLS_REPLY_RESOLUTION, &call_again);

		if (call_again)
			continue;

		/* Delete hold; keep all holds in beginning of array. */
		record->num_holds--;
		if (i < record->num_holds) {
			rte_memcpy(&record->holds[i],
				&record->holds[record->num_holds],
				sizeof(record->holds[i]));
			/*
			 * This cancels out the update of the for loop so we
			 * can redo update of hold at position @i, if needed.
			 */
			i--;
		}
	}
}

static int
lls_add_record(struct lls_cache *cache, const struct ipaddr *addr)
{
	int ret = rte_hash_add_key(cache->hash, &addr->ip);
	if (unlikely(ret == -EINVAL || ret == -ENOSPC)) {
		char ip_str[MAX_INET_ADDRSTRLEN];
		int ret2 = convert_ip_to_str(addr, ip_str, sizeof(ip_str));
		LLS_LOG(ERR, "%s, could not add record for %s\n",
			ret == -EINVAL ? "Invalid params" : "No space",
			ret2 < 0 ? cache->name : ip_str);
	} else
		RTE_VERIFY(ret >= 0);
	return ret;
}

static void
lls_del_record(struct lls_cache *cache, const struct ipaddr *addr)
{
	int32_t ret = rte_hash_del_key(cache->hash, &addr->ip);
	if (unlikely(ret == -ENOENT || ret == -EINVAL)) {
		char ip_str[MAX_INET_ADDRSTRLEN];
		int ret2 = convert_ip_to_str(addr, ip_str, sizeof(ip_str));
		LLS_LOG(ERR, "%s, record for %s not deleted\n",
			ret == -ENOENT ? "No map found" : "Invalid params",
			ret2 < 0 ? cache->name : ip_str);
	}
}

static void
lls_process_hold(struct lls_config *lls_conf, struct lls_hold_req *hold_req)
{
	struct lls_cache *cache = hold_req->cache;
	struct lls_record *record;
	int ret = rte_hash_lookup(cache->hash, &hold_req->addr.ip);

	if (ret == -ENOENT) {
		ret = lls_add_record(cache, &hold_req->addr);
		if (ret < 0)
			return;

		record = &cache->records[ret];
		record->map.stale = true;
		record->map.addr = hold_req->addr;
		record->ts = time(NULL);
		RTE_VERIFY(record->ts >= 0);
		record->holds[0] = hold_req->hold;
		record->num_holds = 1;

		/* Try to resolve record using broadcast. */
		lls_send_request(lls_conf, cache, &hold_req->addr, NULL);

		if (lls_conf->log_level == RTE_LOG_DEBUG)
			lls_cache_dump(cache);
		return;
	} else if (unlikely(ret == -EINVAL)) {
		char ip_str[MAX_INET_ADDRSTRLEN];
		ret = convert_ip_to_str(&hold_req->addr, ip_str,
			sizeof(ip_str));
		LLS_LOG(ERR,
			"Invalid params, could not get %s map; hold failed\n",
			ret < 0 ? cache->name : ip_str);
		return;
	}

	RTE_VERIFY(ret >= 0);
	record = &cache->records[ret];

	if (!record->map.stale) {
		int call_again = false;
		/* Alert requester this map is ready. */
		hold_req->hold.cb(&record->map, hold_req->hold.arg,
			LLS_REPLY_RESOLUTION, &call_again);
		if (!call_again)
			return;
	}
	record->holds[record->num_holds++] = hold_req->hold;

	if (lls_conf->log_level == RTE_LOG_DEBUG)
		lls_cache_dump(cache);
}

static void
lls_process_put(struct lls_config *lls_conf, struct lls_put_req *put_req)
{
	struct lls_cache *cache = put_req->cache;
	struct lls_record *record;
	unsigned int i;
	int ret = rte_hash_lookup(cache->hash, &put_req->addr.ip);

	if (ret == -ENOENT) {
		/*
		 * Not necessarily an error: the block may have indicated
		 * it did not want its callback to be called again, and
		 * all holds have been released on that entry.
		 */
		return;
	} else if (unlikely(ret == -EINVAL)) {
		char ip_str[MAX_INET_ADDRSTRLEN];
		ret = convert_ip_to_str(&put_req->addr, ip_str,
			sizeof(ip_str));
		LLS_LOG(ERR,
			"Invalid params, could not get %s map; put failed\n",
			ret < 0 ? cache->name : ip_str);
		return;
	}

	RTE_VERIFY(ret >= 0);
	record = &cache->records[ret];

	for (i = 0; i < record->num_holds; i++) {
		if (put_req->lcore_id == record->holds[i].lcore_id)
			break;
	}

	/* Requesting lcore not found in holds. */
	if (i == record->num_holds)
		return;

	/*
	 * Alert the requester that its hold will be removed, so it
	 * may free any state that is keeping track of that hold.
	 *
	 * Technically the hold will be removed in the step
	 * below, but alerting the requester first removes the need
	 * to copy the hold into a temporary variable, remove
	 * the hold from record->holds, and then alert the
	 * requester using the temporary variable. This is OK since
	 * there's only one writer.
	 */
	record->holds[i].cb(&record->map, record->holds[i].arg,
		LLS_REPLY_FREE, NULL);

	/* Keep all holds in beginning of array. */
	record->num_holds--;
	if (i < record->num_holds)
		rte_memcpy(&record->holds[i], &record->holds[record->num_holds],
			sizeof(record->holds[i]));

	if (lls_conf->log_level == RTE_LOG_DEBUG)
		lls_cache_dump(cache);
}

void
lls_process_mod(struct lls_config *lls_conf, struct lls_mod_req *mod_req)
{
	struct lls_cache *cache = mod_req->cache;
	struct lls_record *record;
	int changed_ha = false;
	int changed_port = false;
	int changed_stale = false;
	int ret = rte_hash_lookup(cache->hash, &mod_req->addr.ip);

	if (ret == -ENOENT) {
		ret = lls_add_record(cache, &mod_req->addr);
		if (ret < 0)
			return;

		/* Fill-in new record. */
		record = &cache->records[ret];
		rte_ether_addr_copy(&mod_req->ha, &record->map.ha);
		record->map.port_id = mod_req->port_id;
		record->map.stale = false;
		record->map.addr = mod_req->addr;
		record->ts = mod_req->ts;
		record->num_holds = 0;

		if (lls_conf->log_level == RTE_LOG_DEBUG)
			lls_cache_dump(cache);
		return;
	} else if (unlikely(ret == -EINVAL)) {
		char ip_str[MAX_INET_ADDRSTRLEN];
		ret = convert_ip_to_str(&mod_req->addr, ip_str,
			sizeof(ip_str));
		LLS_LOG(ERR,
			"Invalid params, could not get %s map; mod failed\n",
			ret < 0 ? cache->name : ip_str);
		return;
	}

	RTE_VERIFY(ret >= 0);
	record = &cache->records[ret];

	if (!rte_is_same_ether_addr(&mod_req->ha, &record->map.ha)) {
		rte_ether_addr_copy(&mod_req->ha, &record->map.ha);
		changed_ha = true;
	}
	if (record->map.port_id != mod_req->port_id) {
		record->map.port_id = mod_req->port_id;
		changed_port = true;
	}
	if (record->map.stale) {
		record->map.stale = false;
		changed_stale = true;
	}
	record->ts = mod_req->ts;

	if (changed_ha || changed_port || changed_stale) {
		lls_update_subscribers(record);
		if (lls_conf->log_level == RTE_LOG_DEBUG)
			lls_cache_dump(cache);
	}
}

/*
 * According to RFC 792, the ICMP checksum is computed
 * over all of the words in the ICMP "header." This is ambiguous
 * because ICMP messages can have a "header" portion and
 * a "data" portion. More accurately, the checksum is computed
 * over the header *and* data portion, as described by
 * the formats of the individual ICMP message types in RFC 792.
 *
 * @buf is a pointer to the start of the ICMP header.
 * @size is the length of the ICMP message, including
 * both the header and data portion.
 */
unsigned short
icmp_cksum(void *buf, unsigned int size)
{
	unsigned short *buffer = buf;
	unsigned long cksum = 0;

	while (size > 1) {
		cksum += *buffer++;
		size -= sizeof(*buffer);
	}

	if (size)
		cksum += *(unsigned char *)buffer;

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);

	return (unsigned short)(~cksum);
}

static bool
xmit_icmp_ping_reply(struct gatekeeper_if *iface, struct rte_mbuf *pkt)
{
	struct rte_ether_addr eth_addr_tmp;
	struct rte_ether_hdr *icmp_eth = rte_pktmbuf_mtod(pkt,
		struct rte_ether_hdr *);
	struct rte_ipv4_hdr *icmp_ipv4;
	struct rte_icmp_hdr *icmph;

	rte_ether_addr_copy(&icmp_eth->s_addr, &eth_addr_tmp);
	rte_ether_addr_copy(&icmp_eth->d_addr, &icmp_eth->s_addr);
	rte_ether_addr_copy(&eth_addr_tmp, &icmp_eth->d_addr);
	if (iface->vlan_insert) {
		fill_vlan_hdr(icmp_eth, iface->ipv4_vlan_tag_be,
			RTE_ETHER_TYPE_IPV4);
	}

	/* Set-up IPv4 header. */
	icmp_ipv4 = (struct rte_ipv4_hdr *)pkt_out_skip_l2(iface, icmp_eth);
	icmph = (struct rte_icmp_hdr *)ipv4_skip_exthdr(icmp_ipv4);

	icmp_ipv4->time_to_live = IP_DEFTTL;
	switch (icmph->icmp_type) {
	case ICMP_ECHO_REQUEST_TYPE: {
		/*
		 * According to RFC 792 page 13: to form an echo reply
		 * message, the source and destination addresses are simply
		 * reversed, the type code changed to 0, and the checksum
		 * recomputed.
		 */
		rte_be32_t ip_addr_tmp = icmp_ipv4->src_addr;
		icmp_ipv4->src_addr = icmp_ipv4->dst_addr;
		icmp_ipv4->dst_addr = ip_addr_tmp;

		/*
		 * According to RFC 792 page 14:
		 *
		 * (1) the data received in the echo message must be returned in
		 * the echo reply message.
		 *
		 * (2) the identifier and sequence number may be used by
		 * the echo sender to aid in matching the replies with
		 * the echo requests.
		 *
		 * So, we keep these fields unmodified.
		 */
		icmph->icmp_type = ICMP_ECHO_REPLY_TYPE;
		icmph->icmp_code = ICMP_ECHO_REPLY_CODE;

		break;
	}
	case ICMP_MASK_REQUEST_TYPE: {
		uint32_t pkt_size;
		struct in_addr *ip4_mask;

		/*
		 * According to RFC 3021: the 255.255.255.255 IP broadcast
		 * address MUST be used for broadcast Address Mask Replies
		 * in point-to-point links with 31-bit subnet masks.
		 * In other cases, the form {<Network-number>, -1} should be
		 * used.
		 */
		icmp_ipv4->src_addr = icmp_ipv4->dst_addr;
		if (iface->ip4_addr_plen >= 31)
			icmp_ipv4->dst_addr = (uint32_t)-1;
		else {
			icmp_ipv4->dst_addr = (iface->ip4_addr.s_addr |
					(~iface->ip4_mask.s_addr));
		}

		pkt_size = iface->l2_len_out + ipv4_hdr_len(icmp_ipv4) +
			sizeof(*icmph) + sizeof(struct in_addr);
		if (pkt->pkt_len < pkt_size) {
			char *data = rte_pktmbuf_append(pkt, pkt_size -
					pkt->pkt_len);
			if (data == NULL) {
				LLS_LOG(WARNING,
						"Could not append %d bytes of data to the ICMP mask reply packet\n",
						pkt_size -
						pkt->pkt_len);
				return false;
			}
		} else if (pkt->pkt_len > pkt_size) {
			int ret = rte_pktmbuf_trim(pkt, pkt->pkt_len -
					pkt_size);
			if (ret != 0) {
				LLS_LOG(WARNING,
						"Could not remove %d bytes of data at the end of the ICMP mask reply packet\n",
						pkt->pkt_len -
						pkt_size);
				return false;
			}
		}

		icmp_ipv4->total_length = rte_cpu_to_be_16(pkt_size - iface->l2_len_out);
		/* The reply contains the nework's subnet address mask. */
		icmph->icmp_type = ICMP_MASK_REPLY_TYPE;
		icmph->icmp_code = ICMP_MASK_REPLY_CODE;
		ip4_mask = (struct in_addr *)&icmph[1];
		rte_memcpy(ip4_mask, &iface->ip4_mask, sizeof(*ip4_mask));

		break;
	}
	default:
		LLS_LOG(ERR, "Invalide ICMP packet with type %d\n",
				icmph->icmp_type);
		return false;
	}

	pkt->l2_len = iface->l2_len_out;
	pkt->l3_len = ipv4_hdr_len(icmp_ipv4);
	set_ipv4_checksum(iface, pkt, icmp_ipv4);

	icmph->icmp_cksum = 0;
	icmph->icmp_cksum = icmp_cksum(icmph,
		pkt->pkt_len - (pkt->l2_len + pkt->l3_len));
	return true;
}

static void
process_ping_pkts(struct rte_mbuf **pkts, unsigned int num_pkts,
	struct lls_config *lls_conf, struct gatekeeper_if *iface,
	bool (*xmit_reply_fn)(struct gatekeeper_if *, struct rte_mbuf *))
{
	struct rte_mbuf *ping_pkts[num_pkts];
	uint16_t tx_queue;
	struct token_bucket_ratelimit_state *rs;
	unsigned int i;
	unsigned int num_ping_reply_pkts;
	unsigned int num_granted_pkts;

	if (iface == &lls_conf->net->front) {
		tx_queue = lls_conf->tx_queue_front;
		rs = &lls_conf->front_icmp_rs;
	} else {
		tx_queue = lls_conf->tx_queue_back;
		rs = &lls_conf->back_icmp_rs;
	}

	num_granted_pkts = tb_ratelimit_allow_n(num_pkts, rs);

	for (i = 0, num_ping_reply_pkts = 0; num_ping_reply_pkts <
			num_granted_pkts && i < num_pkts; i++) {
		bool succ = (*xmit_reply_fn)(iface, pkts[i]);
		if (succ)
			ping_pkts[num_ping_reply_pkts++] = pkts[i];
		else
			rte_pktmbuf_free(pkts[i]);
	}
	send_pkts(iface->id, tx_queue, num_ping_reply_pkts, ping_pkts);

	/* XXX #435: Adopt rte_pktmbuf_free_bulk() when DPDK is updated. */
	for (; i < num_pkts; i++)
		rte_pktmbuf_free(pkts[i]);
}

static void
process_icmp_pkts(struct lls_config *lls_conf, struct lls_icmp_req *icmp)
{
	struct rte_mbuf *ping_pkts[icmp->num_pkts];
	unsigned int num_ping_pkts = 0;
	struct rte_mbuf *kni_pkts[icmp->num_pkts];
	unsigned int num_kni_pkts = 0;
	int i;

	for (i = 0; i < icmp->num_pkts; i++) {
		struct rte_mbuf *pkt = icmp->pkts[i];
		struct rte_ether_hdr *eth_hdr =
			rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		struct rte_ipv4_hdr *ip4hdr;
		struct rte_icmp_hdr *icmphdr;
		size_t l2_len = pkt_in_l2_hdr_len(pkt);
		char src_ip_buf[INET_ADDRSTRLEN];
		const char *src_ip_or_err;

		pkt_in_skip_l2(pkt, eth_hdr, (void **)&ip4hdr);
		if (unlikely(pkt->data_len < (ICMP_PKT_MIN_LEN(l2_len) +
				ipv4_hdr_len(ip4hdr) - sizeof(*ip4hdr)))) {
			rte_pktmbuf_free(pkt);
			continue;
		}

		/*
		 * We must check whether the packet is fragmented here because
		 * although match_icmp() checks for it, the ACL rule does not.
		 */
		if (unlikely(rte_ipv4_frag_pkt_is_fragmented(ip4hdr))) {
			src_ip_or_err = inet_ntop(AF_INET, &ip4hdr->src_addr,
				src_ip_buf, sizeof(src_ip_buf));
			if (unlikely(!src_ip_or_err))
				src_ip_or_err = "(could not convert IP to string)";

			LLS_LOG(WARNING,
				"Received fragmented ICMP packets destined to this server on the %s interface from source IP %s\n",
				icmp->iface->name, src_ip_or_err);
			rte_pktmbuf_free(pkt);
			continue;
		}

		/*
		 * We don't need to make sure the next header is ICMP
		 * because both match_icmp() and the ACL rule already check.
		 */

		icmphdr = (struct rte_icmp_hdr *)ipv4_skip_exthdr(ip4hdr);

		if ((icmphdr->icmp_type == ICMP_ECHO_REQUEST_TYPE &&
				icmphdr->icmp_code == ICMP_ECHO_REQUEST_CODE) ||
				(icmphdr->icmp_type == ICMP_MASK_REQUEST_TYPE &&
				icmphdr->icmp_code == ICMP_MASK_REQUEST_CODE)) {
			ping_pkts[num_ping_pkts++] = pkt;
			continue;
		}

		if (icmphdr->icmp_type == ICMP_ECHO_REPLY_TYPE &&
				icmphdr->icmp_code == ICMP_ECHO_REPLY_CODE) {
			kni_pkts[num_kni_pkts++] = pkt;
			continue;
		}

		src_ip_or_err = inet_ntop(AF_INET, &ip4hdr->src_addr,
			src_ip_buf, sizeof(src_ip_buf));
		if (unlikely(!src_ip_or_err))
			src_ip_or_err = "(could not convert IP to string)";

		if (icmphdr->icmp_type == ICMP_DEST_UNREACHABLE_TYPE &&
				icmphdr->icmp_code == ICMP_FRAG_REQ_DF_CODE) {
			LLS_LOG(ERR, "Received \"Fragmentation required, and DF flag set\" ICMP packet on the %s interface from source IP %s; check MTU along path\n",
				icmp->iface->name, src_ip_or_err);
		} else {
			LLS_LOG(INFO, "Received ICMP packet with type %hhu and code %hhu on the %s interface from source IP %s\n",
				icmphdr->icmp_type, icmphdr->icmp_code,
				icmp->iface->name, src_ip_or_err);
		}
		rte_pktmbuf_free(pkt);
	}

	if (num_ping_pkts > 0)
		process_ping_pkts(ping_pkts, num_ping_pkts,
			lls_conf, icmp->iface, xmit_icmp_ping_reply);

	if (num_kni_pkts > 0)
		cps_submit_direct(kni_pkts, num_kni_pkts, icmp->iface);
}

static bool
xmit_icmp6_ping_reply(struct gatekeeper_if *iface, struct rte_mbuf *pkt)
{
	/*
	 * The ICMPv6 header offset in terms of the
	 * beginning of the IPv6 header.
	 */
	int icmpv6_offset;
	uint8_t nexthdr;
	struct rte_ether_addr eth_addr_tmp;
	struct rte_ether_hdr *icmp_eth = rte_pktmbuf_mtod(pkt,
		struct rte_ether_hdr *);
	struct rte_ipv6_hdr *icmp_ipv6;
	struct icmpv6_hdr *icmpv6_hdr;
	size_t l2_len = pkt_in_l2_hdr_len(pkt);

	rte_ether_addr_copy(&icmp_eth->s_addr, &eth_addr_tmp);
	rte_ether_addr_copy(&icmp_eth->d_addr, &icmp_eth->s_addr);
	rte_ether_addr_copy(&eth_addr_tmp, &icmp_eth->d_addr);
	if (iface->vlan_insert) {
		fill_vlan_hdr(icmp_eth, iface->ipv6_vlan_tag_be,
			RTE_ETHER_TYPE_IPV6);
	}

	/* Set-up IPv6 header. */
	icmp_ipv6 = (struct rte_ipv6_hdr *)pkt_out_skip_l2(iface, icmp_eth);

	/*
	 * The IP Hop Limit field must be 255 as required by
	 * RFC 4861, sections 7.1.1 and 7.1.2.
	 */
	icmp_ipv6->hop_limits = 255;
	/*
	 * According to RFC 4443 section 4.2, the Destination Address of an
	 * ICMPv6 Echo Reply message is copied from the Source Address field
	 * of the invoking Echo Request packet.
	 */
	rte_memcpy(icmp_ipv6->dst_addr, icmp_ipv6->src_addr,
		sizeof(icmp_ipv6->dst_addr));
	/*
	 * According to RFC 4443 section 4.2, in case an Echo Request message
	 * was sent to an IPv6 multicast or anycast address,
	 * the source address of the reply MUST be a unicast address
	 * belonging to the interface on which the Echo Request message
	 * was received.
	 */
	rte_memcpy(icmp_ipv6->src_addr, iface->ip6_addr.s6_addr,
		sizeof(icmp_ipv6->src_addr));

	/*
	 * Set-up ICMPv6 header.
	 *
	 * We don't need to make sure the next header is ICMPv6
	 * or verify the format of the extension headers. See
	 * process_icmpv6_pkts() and match_icmp6().
	 */
	icmpv6_offset = ipv6_skip_exthdr(icmp_ipv6, pkt->data_len - l2_len,
		&nexthdr);
	RTE_VERIFY(icmpv6_offset >= 0);
	icmpv6_hdr = (struct icmpv6_hdr *)((uint8_t *)icmp_ipv6 +
		icmpv6_offset);

	icmpv6_hdr->type = ICMPV6_ECHO_REPLY_TYPE;
	icmpv6_hdr->code = ICMPV6_ECHO_REPLY_CODE;
	icmpv6_hdr->cksum = 0; /* Calculated below. */

	/*
	 * According to RFC 4443 section 4.2, the other parts
	 * (i.e., identifier, sequence number and data) of the Echo reply
	 * message should be from the invoking Echo Request message.
	 *
	 * We keep these fields unmodified.
	 */

	icmpv6_hdr->cksum = rte_ipv6_icmpv6_cksum(icmp_ipv6, icmpv6_hdr);
	return true;
}

static void
process_icmp6_pkts(struct lls_config *lls_conf, struct lls_icmp6_req *icmp6)
{
	struct rte_mbuf *ping6_pkts[icmp6->num_pkts];
	unsigned int num_ping6_pkts = 0;
	struct rte_mbuf *kni_pkts[icmp6->num_pkts];
	unsigned int num_kni_pkts = 0;
	int i;

	for (i = 0; i < icmp6->num_pkts; i++) {
		struct rte_mbuf *pkt = icmp6->pkts[i];
		/*
		 * The ICMPv6 header offset in terms of the
		 * beginning of the IPv6 header.
		 */
		int icmpv6_offset;
		uint8_t nexthdr;
		struct rte_ether_hdr *eth_hdr =
			rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		struct rte_ipv6_hdr *ip6hdr;
		struct icmpv6_hdr *icmp6_hdr;
		size_t l2_len = pkt_in_l2_hdr_len(pkt);
		char src_ip_buf[INET6_ADDRSTRLEN];
		const char *src_ip_or_err;

		pkt_in_skip_l2(pkt, eth_hdr, (void **)&ip6hdr);

		/*
		 * We must check whether the packet is fragmented here because
		 * although match_icmp6() checks for it, the ACL rule does not.
		 */
		if (unlikely(rte_ipv6_frag_get_ipv6_fragment_header(ip6hdr) !=
				NULL)) {
			src_ip_or_err = inet_ntop(AF_INET6, &ip6hdr->src_addr,
				src_ip_buf, sizeof(src_ip_buf));
			if (unlikely(!src_ip_or_err))
				src_ip_or_err = "(could not convert IP to string)";

			LLS_LOG(WARNING,
				"Received fragmented ICMPv6 packets destined to this server on the %s interface from source IP %s\n",
				icmp6->iface->name, src_ip_or_err);
			rte_pktmbuf_free(pkt);
			continue;
		}

		/*
		 * We don't need to make sure the next header is ICMPv6
		 * because both match_icmp6() and the ACL rule already check.
		 * We also don't need to verify that the header extensions
		 * were not malformed, since if there were extension headers
		 * then match_icmp6() would have already verified them. But
		 * we can at least add an assertion to catch bugs.
		 */

		icmpv6_offset = ipv6_skip_exthdr(ip6hdr,
			pkt->data_len - l2_len, &nexthdr);
		RTE_VERIFY(icmpv6_offset >= 0);
		icmp6_hdr = (struct icmpv6_hdr *)((uint8_t *)ip6hdr +
			icmpv6_offset);

		/* Silently drop ND Router messages to avoid cluttering log. */
		if (pkt_is_nd_router(icmp6_hdr->type, icmp6_hdr->code)) {
			rte_pktmbuf_free(pkt);
			continue;
		}

		/* No other types should have the all nodes multicast addr. */
		if (memcmp(ip6hdr->dst_addr, &ip6_allnodes_mc_addr,
				sizeof(ip6_allnodes_mc_addr)) == 0) {
			rte_pktmbuf_free(pkt);
			continue;
		}

		if (icmp6_hdr->type == ICMPV6_ECHO_REQUEST_TYPE &&
				icmp6_hdr->code == ICMPV6_ECHO_REQUEST_CODE) {
			ping6_pkts[num_ping6_pkts++] = pkt;
			continue;
		}

		if (icmp6_hdr->type == ICMPV6_ECHO_REPLY_TYPE &&
				icmp6_hdr->code == ICMPV6_ECHO_REPLY_CODE) {
			kni_pkts[num_kni_pkts++] = pkt;
			continue;
		}

		if (pkt_is_nd_neighbor(icmp6_hdr->type, icmp6_hdr->code)) {
			if (process_nd(lls_conf, icmp6->iface, pkt) == -1)
				rte_pktmbuf_free(pkt);
			continue;
		}

		src_ip_or_err = inet_ntop(AF_INET6, &ip6hdr->src_addr,
			src_ip_buf, sizeof(src_ip_buf));
		if (unlikely(!src_ip_or_err))
			src_ip_or_err = "(could not convert IP to string)";

		if (icmp6_hdr->type == ICMPV6_PACKET_TOO_BIG_TYPE &&
				icmp6_hdr->code == ICMPV6_PACKET_TOO_BIG_CODE) {
			LLS_LOG(ERR, "Received \"Packet Too Big\" ICMPv6 packet on %s interface from source IP %s; check MTU along path\n",
				icmp6->iface->name, src_ip_or_err);
		} else {
			LLS_LOG(INFO, "Received ICMPv6 packet with type %hhu and code %hhu on %s interface from source IP %s\n",
				icmp6_hdr->type, icmp6_hdr->code,
				icmp6->iface->name, src_ip_or_err);
		}
		rte_pktmbuf_free(pkt);
	}

	if (num_ping6_pkts > 0)
		process_ping_pkts(ping6_pkts, num_ping6_pkts,
			lls_conf, icmp6->iface, xmit_icmp6_ping_reply);

	if (num_kni_pkts > 0)
		cps_submit_direct(kni_pkts, num_kni_pkts, icmp6->iface);
}

unsigned int
lls_process_reqs(struct lls_config *lls_conf)
{
	unsigned int mailbox_burst_size = lls_conf->mailbox_burst_size;
	struct lls_request *reqs[mailbox_burst_size];
	unsigned int count = mb_dequeue_burst(&lls_conf->requests,
		(void **)reqs, mailbox_burst_size);
	unsigned int i;

	for (i = 0; i < count; i++) {
		switch (reqs[i]->ty) {
		case LLS_REQ_HOLD:
			lls_process_hold(lls_conf, &reqs[i]->u.hold);
			break;
		case LLS_REQ_PUT:
			lls_process_put(lls_conf, &reqs[i]->u.put);
			break;
		case LLS_REQ_ARP: {
			struct lls_arp_req *arp = &reqs[i]->u.arp;
			uint16_t tx_queue =
				(arp->iface == &lls_conf->net->front)
				? lls_conf->tx_queue_front
				: lls_conf->tx_queue_back;
			int i;
			for (i = 0; i < arp->num_pkts; i++) {
				struct rte_mbuf *pkt = arp->pkts[i];
				struct rte_ether_hdr *eth_hdr =
					rte_pktmbuf_mtod(pkt,
						struct rte_ether_hdr *);
				struct rte_arp_hdr *arp_hdr =
					rte_pktmbuf_mtod_offset(pkt,
						struct rte_arp_hdr *,
						pkt_in_l2_hdr_len(pkt));
				if (process_arp(lls_conf, arp->iface,
						tx_queue, pkt,
						eth_hdr, arp_hdr) == -1)
					rte_pktmbuf_free(pkt);
			}
			break;
		}
		case LLS_REQ_ICMP:
			process_icmp_pkts(lls_conf, &reqs[i]->u.icmp);
			break;
		case LLS_REQ_ICMP6:
			process_icmp6_pkts(lls_conf, &reqs[i]->u.icmp6);
			break;
		default:
			LLS_LOG(ERR, "Unrecognized request type (%d)\n",
				reqs[i]->ty);
			break;
		}
		mb_free_entry(&lls_conf->requests, reqs[i]);
	}

	return count;
}

int
lls_req(enum lls_req_ty ty, void *req_arg)
{
	struct lls_config *lls_conf = get_lls_conf();
	struct lls_request *req = mb_alloc_entry(&lls_conf->requests);
	int ret;

	if (req == NULL) {
		LLS_LOG(ERR, "Allocation for request of type %d failed", ty);
		return -1;
	}

	req->ty = ty;

	switch (ty) {
	case LLS_REQ_HOLD:
		req->u.hold = *(struct lls_hold_req *)req_arg;
		break;
	case LLS_REQ_PUT:
		req->u.put = *(struct lls_put_req *)req_arg;
		break;
	case LLS_REQ_ARP: {
		struct lls_arp_req *arp_req = (struct lls_arp_req *)req_arg;
		req->u.arp = *arp_req;
		rte_memcpy(req->u.arp.pkts, arp_req->pkts,
			sizeof(arp_req->pkts[0]) * arp_req->num_pkts);
		break;
	}
	case LLS_REQ_ICMP: {
		struct lls_icmp_req *icmp_req =
			(struct lls_icmp_req *)req_arg;
		req->u.icmp = *icmp_req;
		rte_memcpy(req->u.icmp.pkts, icmp_req->pkts,
			sizeof(icmp_req->pkts[0]) * icmp_req->num_pkts);
		break;
	}
	case LLS_REQ_ICMP6: {
		struct lls_icmp6_req *icmp6_req =
			(struct lls_icmp6_req *)req_arg;
		req->u.icmp6 = *icmp6_req;
		rte_memcpy(req->u.icmp6.pkts, icmp6_req->pkts,
			sizeof(icmp6_req->pkts[0]) * icmp6_req->num_pkts);
		break;
	}
	default:
		mb_free_entry(&lls_conf->requests, req);
		LLS_LOG(ERR, "Unknown request type %d failed", ty);
		return -1;
	}

	ret = mb_send_entry(&lls_conf->requests, req);
	if (ret < 0)
		return ret;

	return 0;
}

struct lls_map *
lls_cache_get(struct lls_cache *cache, const struct ipaddr *addr)
{
	int ret = rte_hash_lookup(cache->hash, &addr->ip);
	if (ret < 0)
		return NULL;
	return &cache->records[ret].map;
}

void
lls_cache_scan(struct lls_config *lls_conf, struct lls_cache *cache)
{
	uint32_t iter = 0;
	int32_t index;
	const void *key;
	void *data;
	struct gatekeeper_if *front = &lls_conf->net->front;
	struct gatekeeper_if *back = &lls_conf->net->back;
	time_t now = time(NULL);

	RTE_VERIFY(now >= 0);
	index = rte_hash_iterate(cache->hash, (void *)&key, &data, &iter);
	while (index >= 0) {
		struct lls_record *record = &cache->records[index];
		struct ipaddr *addr = &record->map.addr;
		uint32_t timeout;

		/*
		 * If a map is already stale, continue to
		 * try to resolve it while there's interest.
		 */
		if (record->map.stale) {
			if (record->num_holds > 0)
				lls_send_request(lls_conf, cache, addr, NULL);
			else
				lls_del_record(cache, addr);
			goto next;
		}

		if (record->map.port_id == front->id)
			timeout = cache->front_timeout_sec;
		else if (lls_conf->net->back_iface_enabled &&
				record->map.port_id == back->id)
			timeout = cache->back_timeout_sec;
		else {
			char ip_str[MAX_INET_ADDRSTRLEN];
			int ret = convert_ip_to_str(addr, ip_str,
				sizeof(ip_str));
			LLS_LOG(ERR, "Map for %s has an invalid port %hhu\n",
				ret < 0 ? cache->name : ip_str,
				record->map.port_id);
			lls_del_record(cache, addr);
			goto next;
		}

		if (now - record->ts >= timeout) {
			record->map.stale = true;
			lls_update_subscribers(record);
			if (record->num_holds > 0)
				lls_send_request(lls_conf, cache, addr,
					&record->map.ha);
		} else if (timeout > lls_conf->cache_scan_interval_sec &&
				(now - record->ts >= timeout - lls_conf->
					cache_scan_interval_sec)) {
			/*
			 * If the record is close to being stale,
			 * preemptively send a unicast probe.
			 */
			if (record->num_holds > 0)
				lls_send_request(lls_conf, cache, addr,
					&record->map.ha);
		}
next:
		index = rte_hash_iterate(cache->hash, (void *)&key,
			&data, &iter);
	}

	if (get_lls_conf()->log_level == RTE_LOG_DEBUG)
		lls_cache_dump(cache);
}

void
lls_cache_destroy(struct lls_cache *cache)
{
	rte_hash_free(cache->hash);
	cache->hash = NULL;
	rte_free(cache->records);
	cache->records = NULL;
}

int
lls_cache_init(struct lls_config *lls_conf, struct lls_cache *cache,
	uint32_t key_len)
{
	unsigned int socket_id = rte_lcore_to_socket_id(lls_conf->lcore_id);
	struct rte_hash_parameters lls_cache_params = {
		.name = cache->name,
		.entries = lls_conf->max_num_cache_records < HASH_TBL_MIN_SIZE
			? HASH_TBL_MIN_SIZE
			: lls_conf->max_num_cache_records,
		.reserved = 0,
		.key_len = key_len,
		.hash_func = DEFAULT_HASH_FUNC,
		.hash_func_init_val = 0,
		.socket_id = socket_id,
		/*
		 * Enable concurrency control for race conditions
		 * between writers (LLS) and readers (Dynamic Config).
		 */
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
	};

	cache->records = rte_calloc_socket("lls_records",
		lls_conf->max_num_cache_records, sizeof(*cache->records), 0,
		socket_id);
	if (cache->records == NULL) {
		LLS_LOG(ERR, "Could not allocate %s cache records\n",
			cache->name);
		return -1;
	}

	cache->hash = rte_hash_create(&lls_cache_params);
	if (cache->hash == NULL) {
		LLS_LOG(ERR, "Could not create %s cache hash\n", cache->name);
		goto records;
	}
	return 0;

records:
	lls_cache_destroy(cache);

	return -1;
}
