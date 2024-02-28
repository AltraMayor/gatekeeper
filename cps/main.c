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

/* For gettid(). */
#define _GNU_SOURCE

#include <net/if.h>
#include <unistd.h>

#include "gatekeeper_cps.h"
#include "gatekeeper_l2.h"
#include "gatekeeper_launch.h"
#include "gatekeeper_lls.h"
#include "gatekeeper_log_ratelimit.h"
#include "gatekeeper_varip.h"
#include "kni.h"
#include "rd.h"

static struct cps_config cps_conf;

struct cps_config *
get_cps_conf(void)
{
	return &cps_conf;
}

static int
cleanup_cps(void)
{
	/*
	 * From cps_stage2()
	 */

	/*
	 * rd_event_sock_close() can be called even when the netlink
	 * socket is not open.
	 */
	rd_event_sock_close(&cps_conf);

	kni_free(&cps_conf.back_kni);
	kni_free(&cps_conf.front_kni);

	/*
	 * From cps_stage1() -> assign_cps_queue_ids()
	 */

	destroy_mempool(cps_conf.mp);

	/*
	 * From run_cps()
	 */

	if (cps_conf.gt != NULL)
		gt_conf_put(cps_conf.gt);
	cps_conf.gt = NULL;

	if (cps_conf.gk != NULL)
		gk_conf_put(cps_conf.gk);
	cps_conf.gk = NULL;

	rte_timer_stop(&cps_conf.scan_timer);
	rd_free_coro(&cps_conf);
	destroy_mailbox(&cps_conf.mailbox);
	rte_mempool_free(cps_conf.nd_mp);
	cps_conf.nd_mp = NULL;
	rte_mempool_free(cps_conf.arp_mp);
	cps_conf.arp_mp = NULL;

	return 0;
}

/*
 * Responding to ARP and ND packets from the KNI. If responding to
 * an ARP/ND packet fails, we remove the request from the linked list
 * anyway, forcing the KNI to issue another resolution request.
 */

static void
send_arp_reply_kni(struct cps_config *cps_conf, struct cps_arp_req *arp)
{
	struct gatekeeper_if *iface = arp->iface;
	struct rte_mbuf *created_pkt;
	struct rte_ether_hdr *eth_hdr;
	struct rte_arp_hdr *arp_hdr;
	size_t pkt_size;
	struct cps_kni *kni;
	int ret;

	created_pkt = rte_pktmbuf_alloc(cps_conf->mp);
	if (unlikely(created_pkt == NULL)) {
		G_LOG(ERR, "%s(%s): could not allocate an ARP reply\n",
			__func__, iface->name);
		return;
	}

	pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	created_pkt->data_len = pkt_size;
	created_pkt->pkt_len = pkt_size;

	/*
	 * Set-up Ethernet header. The Ethernet address of the KNI is the
	 * same as that of the Gatekeeper interface, so we use that in
	 * the Ethernet and ARP headers.
	 */
	eth_hdr = rte_pktmbuf_mtod(created_pkt, struct rte_ether_hdr *);
	rte_ether_addr_copy(&arp->ha, &eth_hdr->s_addr);
	rte_ether_addr_copy(&iface->eth_addr, &eth_hdr->d_addr);
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

	/* Set-up ARP header. */
	arp_hdr = (struct rte_arp_hdr *)&eth_hdr[1];
	arp_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
	arp_hdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp_hdr->arp_plen = sizeof(struct in_addr);
	arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
	rte_ether_addr_copy(&arp->ha, &arp_hdr->arp_data.arp_sha);
	rte_memcpy(&arp_hdr->arp_data.arp_sip, &arp->ip,
		sizeof(arp_hdr->arp_data.arp_sip));
	rte_ether_addr_copy(&iface->eth_addr, &arp_hdr->arp_data.arp_tha);
	arp_hdr->arp_data.arp_tip = iface->ip4_addr.s_addr;

	kni = iface == &cps_conf->net->front
		? &cps_conf->front_kni
		: &cps_conf->back_kni;

	ret = kni_tx_burst(kni, &created_pkt, 1);
	if (unlikely(ret != 1)) {
		rte_pktmbuf_free(created_pkt);
		G_LOG(ERR, "%s(%s): could not transmit an ARP reply (ret=%i)\n",
			__func__, iface->name, ret);
	}
}

static void
send_nd_reply_kni(struct cps_config *cps_conf, struct cps_nd_req *nd)
{
	struct gatekeeper_if *iface = nd->iface;
	struct rte_mbuf *created_pkt;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct icmpv6_hdr *icmpv6_hdr;
	struct nd_neigh_msg *nd_msg;
	struct nd_opt_lladdr *nd_opt;
	struct cps_kni *kni;
	int ret;

	created_pkt = rte_pktmbuf_alloc(cps_conf->mp);
	if (unlikely(created_pkt == NULL)) {
		G_LOG(ERR, "%s(%s): could not allocate an ND advertisement\n",
			__func__, iface->name);
		return;
	}

	/* Advertisement will include target link layer address. */
	created_pkt->data_len = ND_NEIGH_PKT_LLADDR_MIN_LEN(sizeof(*eth_hdr));
	created_pkt->pkt_len = created_pkt->data_len;

	/*
	 * Set-up Ethernet header. The Ethernet address of the KNI is the
	 * same as that of the Gatekeeper interface, so we use that in
	 * the Ethernet header.
	 */
	eth_hdr = rte_pktmbuf_mtod(created_pkt, struct rte_ether_hdr *);
	rte_ether_addr_copy(&nd->ha, &eth_hdr->s_addr);
	rte_ether_addr_copy(&iface->eth_addr, &eth_hdr->d_addr);
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

	/* Set-up IPv6 header. */
	ipv6_hdr = (struct rte_ipv6_hdr *)&eth_hdr[1];
	ipv6_hdr->vtc_flow = rte_cpu_to_be_32(IPv6_DEFAULT_VTC_FLOW);
	ipv6_hdr->payload_len = rte_cpu_to_be_16(created_pkt->data_len -
		(sizeof(*eth_hdr) + sizeof(*ipv6_hdr)));
	ipv6_hdr->proto = IPPROTO_ICMPV6;
	/*
	 * The IP Hop Limit field must be 255 as required by
	 * RFC 4861, sections 7.1.1 and 7.1.2.
	 */
	ipv6_hdr->hop_limits = 255;
	rte_memcpy(ipv6_hdr->src_addr, nd->ip, sizeof(ipv6_hdr->dst_addr));
	rte_memcpy(ipv6_hdr->dst_addr, iface->ll_ip6_addr.s6_addr,
		sizeof(ipv6_hdr->dst_addr));

	/* Set-up ICMPv6 header. */
	icmpv6_hdr = (struct icmpv6_hdr *)&ipv6_hdr[1];
	icmpv6_hdr->type = ND_NEIGHBOR_ADVERTISEMENT_TYPE;
	icmpv6_hdr->code = ND_NEIGHBOR_ADVERTISEMENT_CODE;
	icmpv6_hdr->cksum = 0; /* Calculated below. */

	/* Set up ND Advertisement header with target LL addr option. */
	nd_msg = (struct nd_neigh_msg *)&icmpv6_hdr[1];
	nd_msg->flags =
		rte_cpu_to_be_32(LLS_ND_NA_OVERRIDE|LLS_ND_NA_SOLICITED);
	rte_memcpy(nd_msg->target, nd->ip, sizeof(nd_msg->target));
	nd_opt = (struct nd_opt_lladdr *)&nd_msg[1];
	nd_opt->type = ND_OPT_TARGET_LL_ADDR;
	nd_opt->len = 1;
	rte_ether_addr_copy(&nd->ha, &nd_opt->ha);

	icmpv6_hdr->cksum = rte_ipv6_icmpv6_cksum(ipv6_hdr, icmpv6_hdr);

	kni = iface == &cps_conf->net->front
		? &cps_conf->front_kni
		: &cps_conf->back_kni;

	ret = kni_tx_burst(kni, &created_pkt, 1);
	if (unlikely(ret != 1)) {
		rte_pktmbuf_free(created_pkt);
		G_LOG(ERR, "%s(%s): could not transmit an ND advertisement (ret=%i)\n",
			__func__, iface->name, ret);
	}
}

static void
tx_to_kni(struct gatekeeper_if *iface, struct cps_kni *kni,
	struct rte_mbuf **pkts, const uint16_t num_pkts)
{
	uint16_t num_kni;
	uint16_t num_tx;
	uint16_t i;

	if (unlikely(num_pkts == 0))
		return;

	if (!iface->vlan_insert) {
		num_kni = num_pkts;
		goto kni_tx;
	}

	/* Remove VLAN headers before passing to the KNI. */
	num_kni = 0;
	for (i = 0; i < num_pkts; i++) {
		struct rte_ether_hdr *eth_hdr =
			rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
		struct rte_vlan_hdr *vlan_hdr;

		if (unlikely(eth_hdr->ether_type !=
				rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN))) {
			G_LOG(WARNING,
				"%s iface is configured for VLAN but received a non-VLAN packet\n",
				iface->name);
			goto to_kni;
		}

		/* Copy Ethernet header over VLAN header. */
		vlan_hdr = (struct rte_vlan_hdr *)&eth_hdr[1];
		eth_hdr->ether_type = vlan_hdr->eth_proto;
		memmove(RTE_PTR_ADD(eth_hdr, sizeof(struct rte_vlan_hdr)),
			eth_hdr, sizeof(*eth_hdr));

		/* Remove the unneeded bytes from the front of the buffer. */
		if (unlikely(rte_pktmbuf_adj(pkts[i],
				sizeof(struct rte_vlan_hdr)) == NULL)) {
			G_LOG(ERR, "Can't remove VLAN header\n");
			rte_pktmbuf_free(pkts[i]);
			continue;
		}
to_kni:
		pkts[num_kni++] = pkts[i];
	}

kni_tx:
	num_tx = kni_tx_burst(kni, pkts, num_kni);
	if (unlikely(num_tx < num_kni))
		rte_pktmbuf_free_bulk(&pkts[num_tx], num_kni - num_tx);
}

static void
process_reqs(struct cps_config *cps_conf)
{
	unsigned int mailbox_burst_size = cps_conf->mailbox_burst_size;
	struct cps_request *reqs[mailbox_burst_size];
	unsigned int count = mb_dequeue_burst(&cps_conf->mailbox,
		(void **)reqs, mailbox_burst_size);
	unsigned int i;

	for (i = 0; i < count; i++) {
		switch (reqs[i]->ty) {
		case CPS_REQ_DIRECT: {
			struct cps_direct_req *direct = &reqs[i]->u.direct;
			struct cps_kni *kni =
				direct->iface == &cps_conf->net->front
					? &cps_conf->front_kni
					: &cps_conf->back_kni;
			tx_to_kni(direct->iface, kni, direct->pkts,
				direct->num_pkts);
			break;
		}
		case CPS_REQ_ARP: {
			struct cps_arp_req *arp = &reqs[i]->u.arp;
			struct arp_request *entry, *next;

			send_arp_reply_kni(cps_conf, arp);

			list_for_each_entry_safe(entry, next,
					&cps_conf->arp_requests, list) {
				if (arp->ip == entry->addr) {
					list_del(&entry->list);
					rte_mempool_put(cps_conf->arp_mp, entry);
					break;
				}
			}
			break;
		}
		case CPS_REQ_ND: {
			struct cps_nd_req *nd = &reqs[i]->u.nd;
			struct nd_request *entry, *next;

			send_nd_reply_kni(cps_conf, nd);

			list_for_each_entry_safe(entry, next,
					&cps_conf->nd_requests, list) {
				if (ipv6_addrs_equal(nd->ip, entry->addr)) {
					list_del(&entry->list);
					rte_mempool_put(cps_conf->nd_mp, entry);
					break;
				}
			}
			break;
		}
		default:
			G_LOG(ERR, "Unrecognized request type (%d)\n",
				reqs[i]->ty);
			break;
		}
		mb_free_entry(&cps_conf->mailbox, reqs[i]);
	}
}

static void
process_ingress(struct gatekeeper_if *iface, struct cps_kni *kni,
	uint16_t rx_queue, uint16_t cps_max_pkt_burst)
{
	struct rte_mbuf *rx_bufs[cps_max_pkt_burst];
	uint16_t num_rx = rte_eth_rx_burst(iface->id, rx_queue, rx_bufs,
		cps_max_pkt_burst);
	tx_to_kni(iface, kni, rx_bufs, num_rx);
}

static int
cps_pkt_is_nd_neighbor(struct gatekeeper_if *iface,
	struct rte_ether_hdr *eth_hdr, uint16_t pkt_len)
{
	struct rte_ipv6_hdr *ipv6_hdr;
	struct icmpv6_hdr *icmpv6_hdr;

	if (pkt_len < (sizeof(*eth_hdr) + sizeof(*ipv6_hdr) +
			sizeof(*icmpv6_hdr)))
		return false;

	ipv6_hdr = (struct rte_ipv6_hdr *)&eth_hdr[1];
	if (ipv6_hdr->proto != IPPROTO_ICMPV6)
		return false;

	/*
	 * Make sure this is an ND neighbor message and that it was
	 * sent by us (our global address, link-local address, or
	 * either of the solicited-node multicast addresses).
	 */
	icmpv6_hdr = (struct icmpv6_hdr *)&ipv6_hdr[1];
	return pkt_is_nd_neighbor(icmpv6_hdr->type, icmpv6_hdr->code) &&
		(ipv6_addrs_equal(ipv6_hdr->src_addr,
			iface->ll_ip6_addr.s6_addr) ||
		ipv6_addrs_equal(ipv6_hdr->src_addr,
			iface->ip6_addr.s6_addr) ||
		ipv6_addrs_equal(ipv6_hdr->src_addr,
			iface->ip6_mc_addr.s6_addr) ||
		ipv6_addrs_equal(ipv6_hdr->src_addr,
			iface->ll_ip6_mc_addr.s6_addr));
}

static void
process_egress(struct cps_config *cps_conf, struct gatekeeper_if *iface,
	struct cps_kni *kni, uint16_t tx_queue, uint16_t cps_max_pkt_burst)
{
	struct rte_mbuf *bufs[cps_max_pkt_burst];
	struct rte_mbuf *forward_bufs[cps_max_pkt_burst];
	uint16_t num_rx = kni_rx_burst(kni, bufs, cps_max_pkt_burst);
	uint16_t num_forward = 0;
	unsigned int num_tx;
	unsigned int i;

	if (num_rx == 0)
		return;

	for (i = 0; i < num_rx; i++) {
		/* Packets sent by the KNI do not have VLAN headers. */
		struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(bufs[i],
			struct rte_ether_hdr *);
		uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
		switch (ether_type) {
		case RTE_ETHER_TYPE_ARP:
			/* Intercept ARP packet and handle it. */
			kni_process_arp(cps_conf, iface, bufs[i], eth_hdr);
			break;
		case RTE_ETHER_TYPE_IPV6: {
			uint16_t pkt_len = rte_pktmbuf_data_len(bufs[i]);
			if (cps_pkt_is_nd_neighbor(iface, eth_hdr, pkt_len)) {
				/* Intercept ND packet and handle it. */
				kni_process_nd(cps_conf, iface,
					bufs[i], eth_hdr, pkt_len);
				break;
			}
		}
			/* FALLTHROUGH */
		default: {
			/*
			 * Forward all other packets to the interface,
			 * adding a VLAN header if necessary.
			 */
			struct rte_ether_hdr *new_eth_hdr;
			uint16_t vlan_tag_be;

			if (!iface->vlan_insert)
				goto to_eth;

			/* Need to make room for a VLAN header. */
			new_eth_hdr = (struct rte_ether_hdr *)
				rte_pktmbuf_prepend(bufs[i],
					sizeof(struct rte_vlan_hdr));
			if (unlikely(new_eth_hdr == NULL)) {
				G_LOG(ERR, "Can't add a VLAN header\n");
				rte_pktmbuf_free(bufs[i]);
				continue;
			}

			memmove(new_eth_hdr, eth_hdr, sizeof(*new_eth_hdr));
			vlan_tag_be = ether_type == RTE_ETHER_TYPE_IPV4 ?
				iface->ipv4_vlan_tag_be : iface->ipv6_vlan_tag_be;
			fill_vlan_hdr(new_eth_hdr, vlan_tag_be, ether_type);
to_eth:
			forward_bufs[num_forward++] = bufs[i];
			break;
		}
		}
	}

	num_tx = rte_eth_tx_burst(iface->id, tx_queue,
		forward_bufs, num_forward);
	if (unlikely(num_tx < num_forward))
		rte_pktmbuf_free_bulk(&forward_bufs[num_tx], num_forward - num_tx);
}

static int
cps_proc(void *arg)
{
	struct cps_config *cps_conf = (struct cps_config *)arg;
	struct net_config *net_conf = cps_conf->net;

	struct gatekeeper_if *front_iface = &net_conf->front;
	struct gatekeeper_if *back_iface = &net_conf->back;
	struct cps_kni *front_kni = &cps_conf->front_kni;
	struct cps_kni *back_kni = &cps_conf->back_kni;

	/*
	 * CAP_NET_ADMIN: allow RTNetlink communication between the CPS and
	 *			routing daemons.
	 * CAP_SYS_MODULE: remove the rte_kni kernel module while exiting.
	 */
	cap_value_t caps[] = {CAP_NET_ADMIN, CAP_SYS_MODULE};

	G_LOG(NOTICE, "The CPS block is running at tid = %u\n", gettid());

	if (needed_caps(RTE_DIM(caps), caps) < 0) {
		G_LOG(ERR, "Could not set needed capabilities\n");
		exiting = true;
	}

	while (likely(!exiting)) {
		/*
		 * Read in IPv4 TCP packets that arrive directly
		 * on the Gatekeeper interfaces.
		 */
		if (cps_conf->rx_method_front & RX_METHOD_NIC) {
			process_ingress(front_iface, front_kni,
				cps_conf->rx_queue_front,
				cps_conf->front_max_pkt_burst);
		}
		if (net_conf->back_iface_enabled &&
				cps_conf->rx_method_back & RX_METHOD_NIC) {
			process_ingress(back_iface, back_kni,
				cps_conf->rx_queue_back,
				cps_conf->back_max_pkt_burst);
		}

		/*
		 * Process any requests made to the CPS block.
		 * The mailbox is used regardless of what RX
		 * methods are used, since it handles requests
		 * from the KNI.
		 */
		process_reqs(cps_conf);

		/*
		 * Read in packets from KNI interfaces, and
		 * transmit to respective Gatekeeper interfaces.
		 */
		process_egress(cps_conf, front_iface, front_kni,
			cps_conf->tx_queue_front,
			cps_conf->front_max_pkt_burst);
		if (net_conf->back_iface_enabled)
			process_egress(cps_conf, back_iface, back_kni,
				cps_conf->tx_queue_back,
				cps_conf->back_max_pkt_burst);

		/* Periodically scan resolution requests from KNIs. */
		rte_timer_manage();

		/* Read in routing table updates and update LPM table. */
		rd_process_events(cps_conf);
	}

	G_LOG(NOTICE, "The CPS block is exiting\n");

	return cleanup_cps();
}

int
cps_submit_direct(struct rte_mbuf **pkts, unsigned int num_pkts,
	struct gatekeeper_if *iface)
{
	struct cps_config *cps_conf = get_cps_conf();
	struct cps_request *req = mb_alloc_entry(&cps_conf->mailbox);
	int ret;

	RTE_VERIFY(num_pkts <= cps_conf->mailbox_max_pkt_burst);

	if (req == NULL) {
		G_LOG(ERR, "%s: allocation of mailbox message failed\n",
			__func__);
		ret = -ENOMEM;
		goto free_pkts;
	}

	req->ty = CPS_REQ_DIRECT;
	req->u.direct.num_pkts = num_pkts;
	req->u.direct.iface = iface;
	rte_memcpy(req->u.direct.pkts, pkts,
		sizeof(*req->u.direct.pkts) * num_pkts);

	ret = mb_send_entry(&cps_conf->mailbox, req);
	if (ret < 0) {
		G_LOG(ERR, "%s: failed to enqueue message to mailbox\n",
			__func__);
		goto free_pkts;
	}

	return 0;

free_pkts:
	rte_pktmbuf_free_bulk(pkts, num_pkts);
	return ret;
}

static int
assign_cps_queue_ids(struct cps_config *cps_conf)
{
	int ret;
	/*
	 * Take the packets created for processing requests from mailbox
	 * as well as the packets in the KNI into account.
	 */
	unsigned int total_pkt_burst = 2 * cps_conf->total_pkt_burst +
		cps_conf->mailbox_burst_size;
	unsigned int num_mbuf;

	/* The front NIC doesn't have hardware support. */
	if (!cps_conf->net->front.rss)
		total_pkt_burst -= cps_conf->front_max_pkt_burst;

	/* The back NIC is enabled but doesn't have hardware support. */
	if (cps_conf->net->back_iface_enabled && !cps_conf->net->back.rss)
		total_pkt_burst -= cps_conf->back_max_pkt_burst;

	/*
	 * Each KNI interface needs at least (cps_conf->kni_queue_size) packets
	 * per queue. There are two queues per interface: 1 RX and 1 TX queues.
	 */
	total_pkt_burst += 2 * cps_conf->kni_queue_size;
	if (cps_conf->net->back_iface_enabled)
		total_pkt_burst += 2 * cps_conf->kni_queue_size;

	num_mbuf = calculate_mempool_config_para("cps",
		cps_conf->net, total_pkt_burst);
	cps_conf->mp = create_pktmbuf_pool("cps",
		cps_conf->lcore_id, num_mbuf);
	if (cps_conf->mp == NULL) {
		ret = -1;
		goto fail;
	}

	/*
	 * CPS should only get its own RX queue if RSS is enabled,
	 * even if ntuple filter is not enabled.
	 *
	 * If RSS is disabled, then the network configuration can
	 * tell that it should ignore all other blocks' requests
	 * for queues and just allocate one RX queue.
	 *
	 * If RSS is enabled, then CPS has already informed the
	 * network configuration that it will be using a queue.
	 * The network configuration will crash if CPS doesn't
	 * configure that queue, so it still should, even if
	 * ntuple filter is not supported and CPS will not use it.
	 */

	if (cps_conf->net->front.rss) {
		ret = get_queue_id(&cps_conf->net->front, QUEUE_TYPE_RX,
			cps_conf->lcore_id, cps_conf->mp);
		if (ret < 0)
			goto fail;
		cps_conf->rx_queue_front = ret;
	}

	ret = get_queue_id(&cps_conf->net->front, QUEUE_TYPE_TX,
		cps_conf->lcore_id, NULL);
	if (ret < 0)
		goto fail;
	cps_conf->tx_queue_front = ret;

	if (cps_conf->net->back_iface_enabled) {
		if (cps_conf->net->back.rss) {
			ret = get_queue_id(&cps_conf->net->back, QUEUE_TYPE_RX,
				cps_conf->lcore_id, cps_conf->mp);
			if (ret < 0)
				goto fail;
			cps_conf->rx_queue_back = ret;
		}

		ret = get_queue_id(&cps_conf->net->back, QUEUE_TYPE_TX,
			cps_conf->lcore_id, NULL);
		if (ret < 0)
			goto fail;
		cps_conf->tx_queue_back = ret;
	}

	return 0;

fail:
	G_LOG(ERR, "Cannot assign queues\n");
	return ret;
}

static void
cps_scan(__attribute__((unused)) struct rte_timer *timer, void *arg)
{
	struct cps_config *cps_conf = (struct cps_config *)arg;
	if (arp_enabled(cps_conf->lls)) {
		struct arp_request *entry, *next;
		list_for_each_entry_safe(entry, next, &cps_conf->arp_requests,
				list) {
			if (entry->stale) {
				/*
				 * It's possible that if this request
				 * was recently satisfied the callback
				 * has already been disabled, but it's
				 * safe to issue an extra put_arp() here.
				 */
				put_arp((struct in_addr *)&entry->addr,
					cps_conf->lcore_id);
				list_del(&entry->list);
				rte_mempool_put(cps_conf->arp_mp, entry);
			} else
				entry->stale = true;
		}
	}
	if (nd_enabled(cps_conf->lls)) {
		struct nd_request *entry, *next;
		list_for_each_entry_safe(entry, next, &cps_conf->nd_requests,
				list) {
			if (entry->stale) {
				/* Same as above -- this may be unnecessary. */
				put_nd((struct in6_addr *)entry->addr,
					cps_conf->lcore_id);
				list_del(&entry->list);
				rte_mempool_put(cps_conf->nd_mp, entry);
			} else
				entry->stale = true;
		}
	}
}

static int
cps_stage1(void *arg)
{
	struct cps_config *cps_conf = arg;
	int ret = assign_cps_queue_ids(cps_conf);
	if (unlikely(ret < 0))
		cleanup_cps();
	return ret;
}

/*
 * Match the packet if it fails to be classifed by ACL rules.
 * If it's a TCP packet, then submit it to the CPS block.
 *
 * Return values: 0 for successful match, and -ENOENT for no matching.
 */
static int
match_tcp4(struct rte_mbuf *pkt, struct gatekeeper_if *iface)
{
	const uint16_t BE_ETHER_TYPE_IPv4 =
		rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	struct rte_ether_hdr *eth_hdr =
		rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	struct rte_ipv4_hdr *ip4hdr;
	uint16_t ether_type_be = pkt_in_skip_l2(pkt, eth_hdr, (void **)&ip4hdr);
	size_t l2_len = pkt_in_l2_hdr_len(pkt);
	uint16_t minimum_size = l2_len + sizeof(struct rte_ipv4_hdr);

	if (unlikely(ether_type_be != BE_ETHER_TYPE_IPv4))
		return -ENOENT;

	if (pkt->data_len < minimum_size)
		return -ENOENT;

	if (ip4hdr->dst_addr != iface->ip4_addr.s_addr)
		return -ENOENT;

	if (ip4hdr->next_proto_id != IPPROTO_TCP)
		return -ENOENT;

	return 0;
}

/*
 * Match the packet if it fails to be classifed by ACL rules.
 * If it's a TCP packet, then submit it to the CPS block.
 *
 * Return values: 0 for successful match, and -ENOENT for no matching.
 */
static int
match_tcp6(struct rte_mbuf *pkt, struct gatekeeper_if *iface)
{
	/*
	 * The TCP header offset in terms of the
	 * beginning of the IPv6 header.
	 */
	int tcp_offset;
	uint8_t nexthdr;
	const uint16_t BE_ETHER_TYPE_IPv6 =
		rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
	struct rte_ether_hdr *eth_hdr =
		rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	struct rte_ipv6_hdr *ip6hdr;
	uint16_t ether_type_be = pkt_in_skip_l2(pkt, eth_hdr, (void **)&ip6hdr);
	size_t l2_len = pkt_in_l2_hdr_len(pkt);
	uint16_t minimum_size = l2_len + sizeof(struct rte_ipv6_hdr);

	if (unlikely(ether_type_be != BE_ETHER_TYPE_IPv6))
		return -ENOENT;

	if (pkt->data_len < minimum_size)
		return -ENOENT;

	if ((memcmp(ip6hdr->dst_addr, &iface->ip6_addr,
			sizeof(iface->ip6_addr)) != 0))
		return -ENOENT;

	tcp_offset = ipv6_skip_exthdr(ip6hdr, pkt->data_len - l2_len, &nexthdr);
	if (tcp_offset < 0 || nexthdr != IPPROTO_TCP)
		return -ENOENT;

	return 0;
}

static int
add_tcp_filters(struct gatekeeper_if *iface, uint16_t rx_queue,
	uint8_t *rx_method)
{
	int ret;

	if (ipv4_if_configured(iface)) {
		ret = ipv4_pkt_filter_add(iface, iface->ip4_addr.s_addr,
			0, 0, 0, 0, IPPROTO_TCP, rx_queue,
			cps_submit_direct, match_tcp4, rx_method);
		if (ret < 0) {
			G_LOG(ERR,
				"Could not add IPv4 TCP filter on %s iface\n",
				iface->name);
			return ret;
		}
	}

	if (ipv6_if_configured(iface)) {
		ret = ipv6_pkt_filter_add(iface,
			(rte_be32_t *)&iface->ip6_addr.s6_addr,
			0, 0, 0, 0, IPPROTO_TCP, rx_queue,
			cps_submit_direct, match_tcp6, rx_method);
		if (ret < 0) {
			G_LOG(ERR,
				"Could not add IPv6 TCP filter on %s iface\n",
				iface->name);
			return ret;
		}
	}

	return 0;
}

static int
cps_stage2(void *arg)
{
	struct cps_config *cps_conf = arg;
	int ret;

	ret = add_tcp_filters(&cps_conf->net->front, cps_conf->rx_queue_front,
		&cps_conf->rx_method_front);
	if (ret < 0) {
		G_LOG(ERR, "Failed to add TCP filters on the front iface");
		goto error;
	}

	ret = kni_create(&cps_conf->front_kni, &cps_conf->net->front,
		cps_conf->mp, cps_conf->kni_queue_size);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(): failed to create KNI for \"%s\" interface (errno=%i): %s\n",
			__func__, cps_conf->net->front.name,
			-ret, strerror(-ret));
		goto error;
	}

	if (cps_conf->net->back_iface_enabled) {
		ret = add_tcp_filters(&cps_conf->net->back,
			cps_conf->rx_queue_back, &cps_conf->rx_method_back);
		if (ret < 0) {
			G_LOG(ERR, "Failed to add TCP filters on the back iface");
			goto error;
		}

		ret = kni_create(&cps_conf->back_kni, &cps_conf->net->back,
			cps_conf->mp, cps_conf->kni_queue_size);
		if (unlikely(ret < 0)) {
			G_LOG(ERR, "%s(): failed to create KNI for \"%s\" interface (errno=%i): %s\n",
				__func__, cps_conf->net->back.name,
				-ret, strerror(-ret));
			goto error;
		}
	}

	ret = rd_event_sock_open(cps_conf);
	if (ret < 0) {
		G_LOG(ERR, "Failed to open routing daemon event socket\n");
		goto error;
	}

	return 0;

error:
	cleanup_cps();
	return ret;
}

int
run_cps(struct net_config *net_conf, struct gk_config *gk_conf,
	struct gt_config *gt_conf, struct cps_config *cps_conf,
	struct lls_config *lls_conf)
{
	int ret;
	int ele_size;
	uint16_t front_inc, back_inc = 0;
	unsigned int socket_id = rte_lcore_to_socket_id(cps_conf->lcore_id);

	if (net_conf == NULL || (gk_conf == NULL && gt_conf == NULL) ||
			cps_conf == NULL || lls_conf == NULL) {
		ret = -1;
		goto out;
	}

	log_ratelimit_state_init(cps_conf->lcore_id,
		cps_conf->log_ratelimit_interval_ms,
		cps_conf->log_ratelimit_burst,
		cps_conf->log_level, "CPS");

	front_inc = cps_conf->front_max_pkt_burst;
	net_conf->front.total_pkt_burst += front_inc;
	if (net_conf->back_iface_enabled) {
		back_inc = cps_conf->back_max_pkt_burst;
		net_conf->back.total_pkt_burst += back_inc;
	}
	cps_conf->total_pkt_burst = front_inc + back_inc;

	ret = net_launch_at_stage1(net_conf, 1, 1, 1, 1, cps_stage1, cps_conf);
	if (ret < 0)
		goto burst;

	ret = launch_at_stage2(cps_stage2, cps_conf);
	if (ret < 0)
		goto stage1;

	ret = launch_at_stage3("cps", cps_proc, cps_conf, cps_conf->lcore_id);
	if (ret < 0)
		goto stage2;

	cps_conf->net = net_conf;
	cps_conf->lls = lls_conf;

	if (cps_conf->nl_pid == 0) {
		G_LOG(ERR, "Option nl_pid must be greater than 0\n");
		goto stage3;
	}

	cps_conf->arp_mp = rte_mempool_create(
		"arp_request_pool", (1 << cps_conf->arp_max_entries_exp) - 1,
		sizeof(struct arp_request), 0, 0, NULL, NULL, NULL, NULL,
		socket_id, MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
	if (cps_conf->arp_mp == NULL) {
		G_LOG(ERR,
			"Can't create mempool arp_request_pool at lcore %u\n",
			cps_conf->lcore_id);
		ret = -1;
		goto stage3;
	}

	cps_conf->nd_mp = rte_mempool_create(
		"nd_request_pool", (1 << cps_conf->nd_max_entries_exp) - 1,
		sizeof(struct nd_request), 0, 0, NULL, NULL, NULL, NULL,
		socket_id, MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
	if (cps_conf->nd_mp == NULL) {
		G_LOG(ERR,
			"Can't create mempool nd_request_pool at lcore %u\n",
			cps_conf->lcore_id);
		ret = -1;
		goto arp_mp;
	}

	if (gk_conf != NULL) {
		cps_conf->mailbox_max_pkt_burst =
			RTE_MAX(gk_conf->front_max_pkt_burst,
				gk_conf->back_max_pkt_burst);
	}

	if (gt_conf != NULL) {
		cps_conf->mailbox_max_pkt_burst =
			RTE_MAX(cps_conf->mailbox_max_pkt_burst,
				gt_conf->max_pkt_burst);
	}

	ele_size = RTE_MAX(sizeof(struct cps_request),
		offsetof(struct cps_request, end_of_header) +
		sizeof(struct cps_direct_req) + sizeof(struct rte_mbuf *) *
		cps_conf->mailbox_max_pkt_burst);

	ret = init_mailbox("cps_mb", cps_conf->mailbox_max_entries_exp,
		ele_size, cps_conf->mailbox_mem_cache_size,
		cps_conf->lcore_id, &cps_conf->mailbox);
	if (ret < 0)
		goto nd_mp;

	ret = rd_alloc_coro(cps_conf);
	if (ret < 0) {
		G_LOG(ERR, "Failed to allocate coroutines\n");
		goto mailbox;
	}

	if (arp_enabled(cps_conf->lls))
		INIT_LIST_HEAD(&cps_conf->arp_requests);
	if (nd_enabled(cps_conf->lls))
		INIT_LIST_HEAD(&cps_conf->nd_requests);

	rte_timer_init(&cps_conf->scan_timer);
	ret = rte_timer_reset(&cps_conf->scan_timer,
		cps_conf->scan_interval_sec * rte_get_timer_hz(),
		PERIODICAL, cps_conf->lcore_id, cps_scan, cps_conf);
	if (ret < 0) {
		G_LOG(ERR, "Cannot set CPS scan timer\n");
		goto coro;
	}

	if (gk_conf != NULL)
		gk_conf_hold(gk_conf);
	cps_conf->gk = gk_conf;

	if (gt_conf != NULL)
		gt_conf_hold(gt_conf);
	cps_conf->gt = gt_conf;

	return 0;

coro:
	rd_free_coro(cps_conf);
mailbox:
	destroy_mailbox(&cps_conf->mailbox);
nd_mp:
	rte_mempool_free(cps_conf->nd_mp);
arp_mp:
	rte_mempool_free(cps_conf->arp_mp);
stage3:
	pop_n_at_stage3(1);
stage2:
	pop_n_at_stage2(1);
stage1:
	pop_n_at_stage1(1);
burst:
	net_conf->front.total_pkt_burst -= front_inc;
	net_conf->back.total_pkt_burst -= back_inc;
out:
	return ret;
}
