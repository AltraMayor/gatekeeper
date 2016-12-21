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

#include <rte_arp.h>

#include "arp.h"
#include "cache.h"

int
iface_arp_enabled(struct net_config *net, struct gatekeeper_if *iface)
{
	/* When @iface is the back, need to make sure it's enabled. */
	if (iface == &net->back)
		return net->back_iface_enabled &&
			iface->configured_proto & GK_CONFIGURED_IPV4;

	/* @iface is the front interface. */
	return iface->configured_proto & GK_CONFIGURED_IPV4;
}

char *
ipv4_str(struct lls_cache *cache, const uint8_t *ip_be, char *buf, size_t len)
{
	struct in_addr ipv4_addr;

	if (sizeof(ipv4_addr) != cache->key_len) {
		RTE_LOG(ERR, GATEKEEPER, "lls: the key size of an ARP entry should be %zu, but it is %"PRIx32"\n",
			sizeof(ipv4_addr), cache->key_len);
		return NULL;
	}

	/* Keep IP address in network order for inet_ntop(). */
	ipv4_addr.s_addr = *(const uint32_t *)ip_be;
	if (inet_ntop(AF_INET, &ipv4_addr, buf, len) == NULL) {
		RTE_LOG(ERR, GATEKEEPER, "lls: %s: failed to convert a number to an IP address (%s)\n",
			__func__, strerror(errno));
		return NULL;
	}

	return buf;
}

void
xmit_arp_req(struct gatekeeper_if *iface, const uint8_t *ip_be,
	const struct ether_addr *ha, uint16_t tx_queue)
{
	struct rte_mbuf *created_pkt;
	struct ether_hdr *eth_hdr;
	struct arp_hdr *arp_hdr;
	size_t pkt_size;
	struct lls_config *lls_conf = get_lls_conf();
	int ret;

	struct rte_mempool *mp = lls_conf->net->gatekeeper_pktmbuf_pool[
		rte_lcore_to_socket_id(lls_conf->lcore_id)];
	created_pkt = rte_pktmbuf_alloc(mp);
	if (created_pkt == NULL) {
		RTE_LOG(ERR, GATEKEEPER,
			"lls: could not alloc a packet for an ARP request\n");
		return;
	}

	pkt_size = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
	created_pkt->data_len = pkt_size;
	created_pkt->pkt_len = pkt_size;

	/* Set-up Ethernet header. */
	eth_hdr = rte_pktmbuf_mtod(created_pkt, struct ether_hdr *);
	ether_addr_copy(&iface->eth_addr, &eth_hdr->s_addr);
	if (ha == NULL)
		memset(&eth_hdr->d_addr, 0xFF, ETHER_ADDR_LEN);
	else
		ether_addr_copy(ha, &eth_hdr->d_addr);
	eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);

	/* Set-up ARP header. */
	arp_hdr = (struct arp_hdr *)(eth_hdr + 1);
	arp_hdr->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
	arp_hdr->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	arp_hdr->arp_hln = ETHER_ADDR_LEN;
	arp_hdr->arp_pln = sizeof(struct in_addr);
	arp_hdr->arp_op = rte_cpu_to_be_16(ARP_OP_REQUEST);
	ether_addr_copy(&iface->eth_addr, &arp_hdr->arp_data.arp_sha);
	arp_hdr->arp_data.arp_sip = iface->ip4_addr.s_addr;
	memset(&arp_hdr->arp_data.arp_tha, 0, ETHER_ADDR_LEN);
	arp_hdr->arp_data.arp_tip = *(const uint32_t *)ip_be;

	ret = rte_eth_tx_burst(iface->id, tx_queue, &created_pkt, 1);
	if (ret <= 0) {
		rte_pktmbuf_free(created_pkt);
		RTE_LOG(ERR, GATEKEEPER,
			"lls: could not transmit an ARP request\n");
	}
}

/*
 * A Gratuitous ARP is an ARP request that serves as an announcement of
 * a neighbor's mapping. The sender and target IP address should be the same,
 * AND the target Ethernet address should be the same as the sender Ethernet
 * address OR zero.
 */
static inline int
is_garp_pkt(const struct arp_hdr *arp_hdr)
{
	return (arp_hdr->arp_data.arp_sip == arp_hdr->arp_data.arp_tip) &&
		(is_zero_ether_addr(&arp_hdr->arp_data.arp_tha) ||
		is_same_ether_addr(&arp_hdr->arp_data.arp_tha,
			&arp_hdr->arp_data.arp_sha));
}

int
process_arp(struct lls_config *lls_conf, struct gatekeeper_if *iface,
	uint16_t tx_queue, struct rte_mbuf *buf, struct ether_hdr *eth_hdr)
{
	struct lls_mod_req mod_req;
	struct arp_hdr *arp_hdr;
	uint16_t pkt_len = rte_pktmbuf_data_len(buf);

	if (pkt_len < sizeof(*eth_hdr) + sizeof(*arp_hdr)) {
		RTE_LOG(ERR, GATEKEEPER, "lls: %s interface received ARP packet of size %hu bytes, but it should be at least %zu bytes\n",
			iface->name, pkt_len,
			sizeof(*eth_hdr) + sizeof(*arp_hdr));
		return -1;
	}

	arp_hdr = rte_pktmbuf_mtod_offset(buf, struct arp_hdr *,
		sizeof(struct ether_hdr));

	if (unlikely(arp_hdr->arp_hrd != rte_cpu_to_be_16(ARP_HRD_ETHER) ||
		     arp_hdr->arp_pro != rte_cpu_to_be_16(ETHER_TYPE_IPv4) ||
		     arp_hdr->arp_hln != ETHER_ADDR_LEN ||
		     arp_hdr->arp_pln != sizeof(struct in_addr)))
		return -1;

	/* TODO If sip is not in the same subnet as our IP address, drop. */

	/* Update cache with source resolution, regardless of operation. */
	mod_req.cache = &lls_conf->arp_cache;
	memcpy(mod_req.ip_be, &arp_hdr->arp_data.arp_sip,
		lls_conf->arp_cache.key_len);
	ether_addr_copy(&arp_hdr->arp_data.arp_sha, &mod_req.ha);
	mod_req.port_id = iface->id;
	mod_req.ts = time(NULL);
	RTE_VERIFY(mod_req.ts >= 0);
	lls_process_mod(lls_conf, &mod_req);

	/*
	 * If it's a Gratuitous ARP or if the target address
	 * is not us, then no response is needed.
	 */
	if (is_garp_pkt(arp_hdr) ||
			(iface->ip4_addr.s_addr != arp_hdr->arp_data.arp_tip))
		return -1;

	switch (rte_be_to_cpu_16(arp_hdr->arp_op)) {
	case ARP_OP_REQUEST: {
		uint16_t num_tx;

		/* Set-up Ethernet header. */
		ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
		ether_addr_copy(&iface->eth_addr, &eth_hdr->s_addr);

		/* Set-up ARP header. */
		arp_hdr->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
		ether_addr_copy(&arp_hdr->arp_data.arp_sha,
			&arp_hdr->arp_data.arp_tha);
		arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;
		ether_addr_copy(&iface->eth_addr, &arp_hdr->arp_data.arp_sha);
		arp_hdr->arp_data.arp_sip = iface->ip4_addr.s_addr;

		/* Need to transmit reply. */
		num_tx = rte_eth_tx_burst(iface->id, tx_queue, &buf, 1);
		if (unlikely(num_tx != 1)) {
			RTE_LOG(NOTICE, GATEKEEPER, "lls: ARP reply failed\n");
			return -1;
		}
		return 0;
	}
	case ARP_OP_REPLY:
		/*
		 * No further action required. Could check to make sure
		 * arp_hdr->arp_data.arp_tha is equal to arp->ether_addr,
		 * but there's nothing that can be done if it's wrong anyway.
		 */
		return -1;
	default:
		RTE_LOG(NOTICE, GATEKEEPER, "lls: %s received an ARP packet with an unknown operation (%hu)\n",
			__func__, rte_be_to_cpu_16(arp_hdr->arp_op));
		return -1;
	}
}

void
print_arp_record(struct lls_cache *cache, struct lls_record *record)
{
	struct lls_map *map = &record->map;
	char ip_buf[cache->key_str_len];
	char *ip_str = ipv4_str(cache, map->ip_be, ip_buf, cache->key_str_len);

	if (ip_str == NULL)
		return;

	if (map->stale)
		RTE_LOG(INFO, GATEKEEPER, "%s: unresolved (%u holds)\n",
			ip_str, record->num_holds);
	else
		RTE_LOG(INFO, GATEKEEPER,
			"%s: %02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8" (port %hhu) (%u holds)\n",
			ip_str,
			map->ha.addr_bytes[0], map->ha.addr_bytes[1],
			map->ha.addr_bytes[2], map->ha.addr_bytes[3],
			map->ha.addr_bytes[4], map->ha.addr_bytes[5],
			map->port_id, record->num_holds);
}
