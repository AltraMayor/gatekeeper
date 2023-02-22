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
#include <arpa/inet.h>

#include <rte_hash.h>
#include <rte_icmp.h>

#include "gatekeeper_cps.h"
#include "gatekeeper_l2.h"
#include "gatekeeper_lls.h"
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

	G_LOG(DEBUG, "LLS cache (%s)\n=====================\n", cache->name);
	index = rte_hash_iterate(cache->hash, &key, &data, &iter);
	while (index >= 0) {
		struct lls_record *record = &cache->records[index];
		struct lls_map *map = &record->map;
		char ip_str[MAX_INET_ADDRSTRLEN];
		int ret = convert_ip_to_str(&map->addr, ip_str,
			sizeof(ip_str));
		if (unlikely(ret < 0)) {
			G_LOG(DEBUG, "Couldn't convert cache record's IP address to string\n");
			goto next;
		}

		if (map->stale) {
			G_LOG(DEBUG, "%s: unresolved (%u holds)\n",
				ip_str, record->num_holds);
		} else {
			G_LOG(DEBUG,
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
		G_LOG(ERR, "%s, could not add record for %s\n",
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
		G_LOG(ERR, "%s, record for %s not deleted\n",
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
		G_LOG(ERR,
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
		G_LOG(ERR,
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
		G_LOG(ERR,
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

static void
submit_icmp_packets(struct rte_mbuf **pkts, unsigned int num_pkts,
	struct gatekeeper_if *iface, struct lls_config *lls_conf)
{
	struct token_bucket_ratelimit_state *rs =
		iface == &lls_conf->net->front
			? &lls_conf->front_icmp_rs
			: &lls_conf->back_icmp_rs;
	unsigned int num_granted_pkts = tb_ratelimit_allow_n(num_pkts, rs);

	cps_submit_direct(pkts, num_granted_pkts, iface);

	rte_pktmbuf_free_bulk(&pkts[num_granted_pkts],
		num_pkts - num_granted_pkts);
}

static void
process_icmp_pkts(struct lls_config *lls_conf, struct lls_icmp_req *icmp)
{
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
			kni_pkts[num_kni_pkts++] = pkt;
			continue;
		}

		/*
		 * We don't need to make sure the next header is ICMP
		 * because both match_icmp() and the ACL rule already check.
		 */

		icmphdr = (struct rte_icmp_hdr *)ipv4_skip_exthdr(ip4hdr);

		if (icmphdr->icmp_type == ICMP_DEST_UNREACHABLE_TYPE &&
				icmphdr->icmp_code == ICMP_FRAG_REQ_DF_CODE) {
			char src_ip_buf[INET_ADDRSTRLEN];
			const char *src_ip_or_err =
				inet_ntop(AF_INET, &ip4hdr->src_addr,
				src_ip_buf, sizeof(src_ip_buf));
			if (unlikely(!src_ip_or_err))
				src_ip_or_err =
					"(could not convert IP to string)";

			G_LOG(ERR, "Received \"Fragmentation required, and DF flag set\" ICMP packet on the %s interface from source IP %s; check MTU along path\n",
				icmp->iface->name, src_ip_or_err);
		}

		kni_pkts[num_kni_pkts++] = pkt;
	}

	if (num_kni_pkts > 0) {
		submit_icmp_packets(kni_pkts, num_kni_pkts, icmp->iface,
			lls_conf);
	}
}

static void
process_icmp6_pkts(struct lls_config *lls_conf, struct lls_icmp6_req *icmp6)
{
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

		pkt_in_skip_l2(pkt, eth_hdr, (void **)&ip6hdr);

		/*
		 * We must check whether the packet is fragmented here because
		 * although match_icmp6() checks for it, the ACL rule does not.
		 */
		if (unlikely(rte_ipv6_frag_get_ipv6_fragment_header(ip6hdr) !=
				NULL)) {
			kni_pkts[num_kni_pkts++] = pkt;
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

		if (pkt_is_nd_neighbor(icmp6_hdr->type, icmp6_hdr->code)) {
			if (process_nd(lls_conf, icmp6->iface, pkt) == -1)
				rte_pktmbuf_free(pkt);
			continue;
		}

		if (icmp6_hdr->type == ICMPV6_PACKET_TOO_BIG_TYPE &&
				icmp6_hdr->code == ICMPV6_PACKET_TOO_BIG_CODE) {
			char src_ip_buf[INET6_ADDRSTRLEN];
			const char *src_ip_or_err =
				inet_ntop(AF_INET6, &ip6hdr->src_addr,
				src_ip_buf, sizeof(src_ip_buf));
			if (unlikely(!src_ip_or_err))
				src_ip_or_err =
					"(could not convert IP to string)";

			G_LOG(ERR, "Received \"Packet Too Big\" ICMPv6 packet on %s interface from source IP %s; check MTU along path\n",
				icmp6->iface->name, src_ip_or_err);
		}

		kni_pkts[num_kni_pkts++] = pkt;
	}

	if (num_kni_pkts > 0) {
		submit_icmp_packets(kni_pkts, num_kni_pkts, icmp6->iface,
			lls_conf);
	}
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
			G_LOG(ERR, "Unrecognized request type (%d)\n",
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
		G_LOG(ERR, "Allocation for request of type %d failed", ty);
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
		G_LOG(ERR, "Unknown request type %d failed", ty);
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
			G_LOG(ERR, "Map for %s has an invalid port %hhu\n",
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
		G_LOG(ERR, "Could not allocate %s cache records\n",
			cache->name);
		return -1;
	}

	cache->hash = rte_hash_create(&lls_cache_params);
	if (cache->hash == NULL) {
		G_LOG(ERR, "Could not create %s cache hash\n", cache->name);
		goto records;
	}
	return 0;

records:
	lls_cache_destroy(cache);

	return -1;
}
