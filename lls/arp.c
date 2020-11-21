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
		return net->back_iface_enabled && ipv4_if_configured(iface);

	/* @iface is the front interface. */
	return ipv4_if_configured(iface);
}

int
ipv4_in_subnet(struct gatekeeper_if *iface, const struct ipaddr *addr)
{
	return ip4_same_subnet(iface->ip4_addr.s_addr, addr->ip.v4.s_addr,
		iface->ip4_mask.s_addr);
}

void
xmit_arp_req(struct gatekeeper_if *iface, const struct ipaddr *addr,
	const struct rte_ether_addr *ha, uint16_t tx_queue)
{
	struct rte_mbuf *created_pkt;
	struct rte_ether_hdr *eth_hdr;
	struct rte_arp_hdr *arp_hdr;
	size_t pkt_size;
	struct lls_config *lls_conf = get_lls_conf();
	int ret;

	created_pkt = rte_pktmbuf_alloc(lls_conf->mp);
	if (created_pkt == NULL) {
		LLS_LOG(ERR, "Could not alloc a packet for an ARP request\n");
		return;
	}

	pkt_size = iface->l2_len_out + sizeof(struct rte_arp_hdr);
	created_pkt->data_len = pkt_size;
	created_pkt->pkt_len = pkt_size;

	/* Set-up Ethernet header. */
	eth_hdr = rte_pktmbuf_mtod(created_pkt, struct rte_ether_hdr *);
	rte_ether_addr_copy(&iface->eth_addr, &eth_hdr->s_addr);
	if (ha == NULL)
		memset(&eth_hdr->d_addr, 0xFF, RTE_ETHER_ADDR_LEN);
	else
		rte_ether_addr_copy(ha, &eth_hdr->d_addr);

	/* Set-up VLAN header. */
	if (iface->vlan_insert)
		fill_vlan_hdr(eth_hdr, iface->ipv4_vlan_tag_be, RTE_ETHER_TYPE_ARP);
	else
		eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

	/* Set-up ARP header. */
	arp_hdr = pkt_out_skip_l2(iface, eth_hdr);
	arp_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
	arp_hdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp_hdr->arp_plen = sizeof(struct in_addr);
	arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);
	rte_ether_addr_copy(&iface->eth_addr, &arp_hdr->arp_data.arp_sha);
	arp_hdr->arp_data.arp_sip = iface->ip4_addr.s_addr;
	memset(&arp_hdr->arp_data.arp_tha, 0, RTE_ETHER_ADDR_LEN);
	arp_hdr->arp_data.arp_tip = addr->ip.v4.s_addr;

	ret = rte_eth_tx_burst(iface->id, tx_queue, &created_pkt, 1);
	if (ret <= 0) {
		rte_pktmbuf_free(created_pkt);
		LLS_LOG(ERR, "Could not transmit an ARP request\n");
	}
}

int
process_arp(struct lls_config *lls_conf, struct gatekeeper_if *iface,
	uint16_t tx_queue, struct rte_mbuf *buf, struct rte_ether_hdr *eth_hdr,
	struct rte_arp_hdr *arp_hdr)
{
	struct ipaddr addr = {
		.proto = RTE_ETHER_TYPE_IPV4,
		.ip.v4.s_addr = arp_hdr->arp_data.arp_sip,
	};
	struct lls_mod_req mod_req;
	uint16_t pkt_len;
	size_t l2_len;
	int ret;

	if (unlikely(!ipv4_if_configured(iface)))
		return -1;

	/* pkt_in_skip_l2() already called by LLS. */
	l2_len = pkt_in_l2_hdr_len(buf);
	pkt_len = rte_pktmbuf_data_len(buf);
	if (pkt_len < l2_len + sizeof(*arp_hdr)) {
		LLS_LOG(ERR, "%s interface received ARP packet of size %hu bytes, but it should be at least %zu bytes\n",
			iface->name, pkt_len,
			l2_len + sizeof(*arp_hdr));
		return -1;
	}

	ret = verify_l2_hdr(iface, eth_hdr, buf->l2_type, "ARP",
		iface->ipv4_vlan_tag_be);
	if (ret < 0)
		return ret;

	if (unlikely(arp_hdr->arp_hardware != rte_cpu_to_be_16(
			RTE_ARP_HRD_ETHER) ||
			arp_hdr->arp_protocol != rte_cpu_to_be_16(
			RTE_ETHER_TYPE_IPV4) ||
			arp_hdr->arp_hlen != RTE_ETHER_ADDR_LEN ||
			arp_hdr->arp_plen != sizeof(struct in_addr)))
		return -1;

	/* If sip is not in the same subnet as our IP address, drop. */
	if (!ipv4_in_subnet(iface, &addr))
		return -1;

	/* Update cache with source resolution, regardless of operation. */
	mod_req.cache = &lls_conf->arp_cache;
	mod_req.addr = addr;
	rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &mod_req.ha);
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

	switch (rte_be_to_cpu_16(arp_hdr->arp_opcode)) {
	case RTE_ARP_OP_REQUEST: {
		uint16_t num_tx;

		/*
		 * We are reusing the frame, but an ARP reply always goes out
		 * the same interface that received it. Therefore, the L2
		 * space of the frame is the same. If needed, the correct
		 * VLAN tag was set in verify_l2_hdr().
		 */

		/* Set-up Ethernet header. */
		rte_ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
		rte_ether_addr_copy(&iface->eth_addr, &eth_hdr->s_addr);

		/* Set-up ARP header. */
		arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
		rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha,
			&arp_hdr->arp_data.arp_tha);
		arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;
		rte_ether_addr_copy(&iface->eth_addr, &arp_hdr->arp_data.arp_sha);
		arp_hdr->arp_data.arp_sip = iface->ip4_addr.s_addr;

		/* Need to transmit reply. */
		num_tx = rte_eth_tx_burst(iface->id, tx_queue, &buf, 1);
		if (unlikely(num_tx != 1)) {
			LLS_LOG(NOTICE, "ARP reply failed\n");
			return -1;
		}
		return 0;
	}
	case RTE_ARP_OP_REPLY:
		/*
		 * No further action required. Could check to make sure
		 * arp_hdr->arp_data.arp_tha is equal to arp->ether_addr,
		 * but there's nothing that can be done if it's wrong anyway.
		 */
		return -1;
	default:
		LLS_LOG(NOTICE, "%s received an ARP packet with an unknown operation (%hu)\n",
			__func__, rte_be_to_cpu_16(arp_hdr->arp_opcode));
		return -1;
	}
}
