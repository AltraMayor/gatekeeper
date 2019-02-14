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

#include <net/if.h>

#include <rte_bus_pci.h>
#include <rte_tcp.h>
#include <rte_cycles.h>

#include "gatekeeper_acl.h"
#include "gatekeeper_cps.h"
#include "gatekeeper_launch.h"
#include "gatekeeper_lls.h"
#include "gatekeeper_varip.h"
#include "gatekeeper_log_ratelimit.h"
#include "kni.h"

/*
 * To capture BGP packets with source port 179 or destination port 179
 * on a global IPv6 address, we need two rules (per interface).
 */
#define NUM_ACL_BGP_RULES (2)

static struct cps_config cps_conf;

int cps_logtype;

struct cps_config *
get_cps_conf(void)
{
	return &cps_conf;
}

static int
cleanup_cps(void)
{
	if (cps_conf.gt != NULL)
		gt_conf_put(cps_conf.gt);
	cps_conf.gt = NULL;

	if (cps_conf.gk != NULL)
		gk_conf_put(cps_conf.gk);
	cps_conf.gk = NULL;

	/*
	 * rd_event_sock_close() can be called even when the netlink
	 * socket is not open, and rte_kni_release() can be passed NULL.
	 */
	rd_event_sock_close(&cps_conf);
	rte_kni_release(cps_conf.back_kni);
	rte_kni_release(cps_conf.front_kni);
	rte_timer_stop(&cps_conf.scan_timer);
	destroy_mailbox(&cps_conf.mailbox);
	rm_kni();
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
	struct ether_hdr *eth_hdr;
	struct arp_hdr *arp_hdr;
	size_t pkt_size;
	struct rte_kni *kni;
	struct rte_mempool *mp;
	int ret;

	mp = cps_conf->net->gatekeeper_pktmbuf_pool[
		rte_lcore_to_socket_id(cps_conf->lcore_id)];
	created_pkt = rte_pktmbuf_alloc(mp);
	if (created_pkt == NULL) {
		CPS_LOG(ERR, "Could not allocate an ARP reply on the %s KNI\n",
			iface->name);
		return;
	}

	pkt_size = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
	created_pkt->data_len = pkt_size;
	created_pkt->pkt_len = pkt_size;

	/*
	 * Set-up Ethernet header. The Ethernet address of the KNI is the
	 * same as that of the Gatekeeper interface, so we use that in
	 * the Ethernet and ARP headers.
	 */
	eth_hdr = rte_pktmbuf_mtod(created_pkt, struct ether_hdr *);
	ether_addr_copy(&arp->ha, &eth_hdr->s_addr);
	ether_addr_copy(&iface->eth_addr, &eth_hdr->d_addr);
	eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);

	/* Set-up ARP header. */
	arp_hdr = (struct arp_hdr *)&eth_hdr[1];
	arp_hdr->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
	arp_hdr->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	arp_hdr->arp_hln = ETHER_ADDR_LEN;
	arp_hdr->arp_pln = sizeof(struct in_addr);
	arp_hdr->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
	ether_addr_copy(&arp->ha, &arp_hdr->arp_data.arp_sha);
	rte_memcpy(&arp_hdr->arp_data.arp_sip, &arp->ip,
		sizeof(arp_hdr->arp_data.arp_sip));
	ether_addr_copy(&iface->eth_addr, &arp_hdr->arp_data.arp_tha);
	arp_hdr->arp_data.arp_tip = iface->ip4_addr.s_addr;

	if (iface == &cps_conf->net->front)
		kni = cps_conf->front_kni;
	else
		kni = cps_conf->back_kni;

	ret = rte_kni_tx_burst(kni, &created_pkt, 1);
	if (ret <= 0) {
		rte_pktmbuf_free(created_pkt);
		CPS_LOG(ERR, "Could not transmit an ARP reply to the %s KNI\n",
			iface->name);
		return;
	}
}

static void
send_nd_reply_kni(struct cps_config *cps_conf, struct cps_nd_req *nd)
{
	struct gatekeeper_if *iface = nd->iface;
	struct rte_mbuf *created_pkt;
	struct ether_hdr *eth_hdr;
	struct ipv6_hdr *ipv6_hdr;
	struct icmpv6_hdr *icmpv6_hdr;
	struct nd_neigh_msg *nd_msg;
	struct nd_opt_lladdr *nd_opt;
	struct rte_kni *kni;
	struct rte_mempool *mp;
	int ret;

	mp = cps_conf->net->gatekeeper_pktmbuf_pool[
		rte_lcore_to_socket_id(cps_conf->lcore_id)];
	created_pkt = rte_pktmbuf_alloc(mp);
	if (created_pkt == NULL) {
		CPS_LOG(ERR,
			"Could not allocate an ND advertisement on the %s KNI\n",
			iface->name);
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
	eth_hdr = rte_pktmbuf_mtod(created_pkt, struct ether_hdr *);
	ether_addr_copy(&nd->ha, &eth_hdr->s_addr);
	ether_addr_copy(&iface->eth_addr, &eth_hdr->d_addr);
	eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);

	/* Set-up IPv6 header. */
	ipv6_hdr = (struct ipv6_hdr *)&eth_hdr[1];
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
	icmpv6_hdr->type = ND_NEIGHBOR_ADVERTISEMENT;
	icmpv6_hdr->code = 0;
	icmpv6_hdr->cksum = 0; /* Calculated below. */

	/* Set up ND Advertisement header with target LL addr option. */
	nd_msg = (struct nd_neigh_msg *)&icmpv6_hdr[1];
	nd_msg->flags =
		rte_cpu_to_be_32(LLS_ND_NA_OVERRIDE|LLS_ND_NA_SOLICITED);
	rte_memcpy(nd_msg->target, nd->ip, sizeof(nd_msg->target));
	nd_opt = (struct nd_opt_lladdr *)&nd_msg[1];
	nd_opt->type = ND_OPT_TARGET_LL_ADDR;
	nd_opt->len = 1;
	ether_addr_copy(&nd->ha, &nd_opt->ha);

	icmpv6_hdr->cksum = rte_ipv6_icmpv6_cksum(ipv6_hdr, icmpv6_hdr);

	if (iface == &cps_conf->net->front)
		kni = cps_conf->front_kni;
	else
		kni = cps_conf->back_kni;

	ret = rte_kni_tx_burst(kni, &created_pkt, 1);
	if (ret <= 0) {
		rte_pktmbuf_free(created_pkt);
		CPS_LOG(ERR,
			"Could not transmit an ND advertisement to the %s KNI\n",
			iface->name);
		return;
	}
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
		case CPS_REQ_BGP: {
			struct cps_bgp_req *bgp = &reqs[i]->u.bgp;
			unsigned int num_tx = rte_kni_tx_burst(bgp->kni,
				bgp->pkts, bgp->num_pkts);
			if (unlikely(num_tx < bgp->num_pkts)) {
				uint16_t j;
				for (j = num_tx; j < bgp->num_pkts; j++)
					rte_pktmbuf_free(bgp->pkts[j]);
			}
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
					rte_free(entry);
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
					rte_free(entry);
					break;
				}
			}
			break;
		}
		default:
			CPS_LOG(ERR, "Unrecognized request type (%d)\n",
				reqs[i]->ty);
			break;
		}
		mb_free_entry(&cps_conf->mailbox, reqs[i]);
	}
}

static void
process_kni_request(struct rte_kni *kni)
{
	/*
	 * Userspace requests to change the device MTU or configure the
	 * device up/down are forwarded from the kernel back to userspace
	 * for DPDK to handle. rte_kni_handle_request() receives those
	 * requests and allows them to be processed.
	 */
	if (rte_kni_handle_request(kni) < 0)
		CPS_LOG(WARNING,
			"%s: error in handling userspace request on KNI %s\n",
			__func__, rte_kni_get_name(kni));
}

static void
process_ingress(struct gatekeeper_if *iface, struct rte_kni *kni,
	uint16_t rx_queue, uint16_t cps_max_pkt_burst)
{
	struct rte_mbuf *rx_bufs[cps_max_pkt_burst];
	uint16_t num_rx = rte_eth_rx_burst(iface->id, rx_queue, rx_bufs,
		cps_max_pkt_burst);
	uint16_t num_kni;
	uint16_t num_tx;
	uint16_t i;

	if (!iface->vlan_insert) {
		num_kni = num_rx;
		goto kni_tx;
	}

	/* Remove any VLAN headers before passing to the KNI. */
	num_kni = 0;
	for (i = 0; i < num_rx; i++) {
		struct ether_hdr *eth_hdr =
			rte_pktmbuf_mtod(rx_bufs[i], struct ether_hdr *);
		struct vlan_hdr *vlan_hdr;

		RTE_VERIFY(num_kni <= i);

		if (unlikely(eth_hdr->ether_type !=
				rte_cpu_to_be_16(ETHER_TYPE_VLAN))) {
			CPS_LOG(WARNING,
				"%s iface is configured for VLAN but received a non-VLAN packet\n",
				iface->name);
			goto to_kni;
		}

		/* Copy Ethernet header over VLAN header. */
		vlan_hdr = (struct vlan_hdr *)&eth_hdr[1];
		eth_hdr->ether_type = vlan_hdr->eth_proto;
		memmove((uint8_t *)eth_hdr + sizeof(struct vlan_hdr), eth_hdr,
			sizeof(*eth_hdr));

		/* Remove the unneeded bytes from the front of the buffer. */
		if (unlikely(rte_pktmbuf_adj(rx_bufs[i],
				sizeof(struct vlan_hdr)) == NULL)) {
			CPS_LOG(ERR, "Can't remove VLAN header\n");
			rte_pktmbuf_free(rx_bufs[i]);
			continue;
		}
to_kni:
		if (unlikely(num_kni < i))
			rx_bufs[num_kni++] = rx_bufs[i];
	}

kni_tx:
	num_tx = rte_kni_tx_burst(kni, rx_bufs, num_kni);
	if (unlikely(num_tx < num_kni)) {
		for (i = num_tx; i < num_kni; i++)
			rte_pktmbuf_free(rx_bufs[i]);
	}
}

static int
pkt_is_nd(struct gatekeeper_if *iface, struct ether_hdr *eth_hdr,
	uint16_t pkt_len)
{
	struct ipv6_hdr *ipv6_hdr;
	struct icmpv6_hdr *icmpv6_hdr;

	if (pkt_len < (sizeof(*eth_hdr) + sizeof(*ipv6_hdr) +
			sizeof(*icmpv6_hdr)))
		return false;

	ipv6_hdr = (struct ipv6_hdr *)&eth_hdr[1];
	if (ipv6_hdr->proto != IPPROTO_ICMPV6)
		return false;

	/*
	 * Make sure this is an ND neighbor message and that it was
	 * sent by us (our global address, link-local address, or
	 * either of the solicited-node multicast addresses.
	 */
	icmpv6_hdr = (struct icmpv6_hdr *)&ipv6_hdr[1];
	return (icmpv6_hdr->type == ND_NEIGHBOR_SOLICITATION ||
			icmpv6_hdr->type == ND_NEIGHBOR_ADVERTISEMENT) &&
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
	struct rte_kni *kni, uint16_t tx_queue, uint16_t cps_max_pkt_burst)
{
	struct rte_mbuf *bufs[cps_max_pkt_burst];
	struct rte_mbuf *forward_bufs[cps_max_pkt_burst];
	uint16_t num_rx = rte_kni_rx_burst(kni, bufs, cps_max_pkt_burst);
	uint16_t num_forward = 0;
	unsigned int num_tx;
	unsigned int i;

	if (num_rx == 0)
		return;

	for (i = 0; i < num_rx; i++) {
		/* Packets sent by the KNI do not have VLAN headers. */
		struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(bufs[i],
			struct ether_hdr *);
		switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
		case ETHER_TYPE_ARP:
			/* Intercept ARP packet and handle it. */
			kni_process_arp(cps_conf, iface, bufs[i], eth_hdr);
			break;
		case ETHER_TYPE_IPv6: {
			uint16_t pkt_len = rte_pktmbuf_data_len(bufs[i]);
			if (pkt_is_nd(iface, eth_hdr, pkt_len)) {
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
			struct ether_hdr *new_eth_hdr;

			if (!iface->vlan_insert)
				goto to_eth;

			/* Need to make room for a VLAN header. */
			new_eth_hdr = (struct ether_hdr *)
				rte_pktmbuf_prepend(bufs[i],
					sizeof(struct vlan_hdr));
			if (unlikely(new_eth_hdr == NULL)) {
				CPS_LOG(ERR, "Can't add a VLAN header\n");
				rte_pktmbuf_free(bufs[i]);
				continue;
			}

			memmove(new_eth_hdr, eth_hdr, sizeof(*new_eth_hdr));
			fill_vlan_hdr(new_eth_hdr, iface->vlan_tag_be,
				rte_be_to_cpu_16(eth_hdr->ether_type));
to_eth:
			forward_bufs[num_forward++] = bufs[i];
			break;
		}
		}
	}

	num_tx = rte_eth_tx_burst(iface->id, tx_queue,
		forward_bufs, num_forward);
	if (unlikely(num_tx < num_forward)) {
		for (i = num_tx; i < num_forward; i++)
			rte_pktmbuf_free(forward_bufs[i]);
	}
}

static int
cps_proc(void *arg)
{
	struct cps_config *cps_conf = (struct cps_config *)arg;
	struct net_config *net_conf = cps_conf->net;

	struct gatekeeper_if *front_iface = &net_conf->front;
	struct gatekeeper_if *back_iface = &net_conf->back;
	struct rte_kni *front_kni = cps_conf->front_kni;
	struct rte_kni *back_kni = cps_conf->back_kni;

	CPS_LOG(NOTICE, "The CPS block is running at lcore = %u\n",
		cps_conf->lcore_id);

	while (likely(!exiting)) {
		/*
		 * Read in IPv4 BGP packets that arrive directly
		 * on the Gatekeeper interfaces.
		 */
		if (hw_filter_ntuple_available(front_iface)) {
			process_ingress(front_iface, front_kni,
				cps_conf->rx_queue_front,
				cps_conf->front_max_pkt_burst);
		}
		process_kni_request(front_kni);

		if (net_conf->back_iface_enabled) {
			if (hw_filter_ntuple_available(back_iface)) {
				process_ingress(back_iface, back_kni,
					cps_conf->rx_queue_back,
					cps_conf->back_max_pkt_burst);
			}
			process_kni_request(back_kni);
		}

		/*
		 * Process any requests made to the CPS block, including
		 * IPv4 and IPv6 BGP packets that arrived via an ACL.
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
		kni_cps_rd_event(cps_conf);
	}

	CPS_LOG(NOTICE, "The CPS block at lcore = %u is exiting\n",
		cps_conf->lcore_id);

	return cleanup_cps();
}

static int
submit_bgp(struct rte_mbuf **pkts, unsigned int num_pkts,
	struct gatekeeper_if *iface)
{
	struct cps_config *cps_conf = get_cps_conf();
	struct cps_request *req = mb_alloc_entry(&cps_conf->mailbox);
	int ret;
	unsigned int i;

	RTE_VERIFY(num_pkts <= cps_conf->mailbox_max_pkt_burst);

	if (req == NULL) {
		CPS_LOG(ERR, "%s: allocation of mailbox message failed\n",
			__func__);
		ret = -ENOMEM;
		goto free_pkts;
	}

	req->ty = CPS_REQ_BGP;
	req->u.bgp.num_pkts = num_pkts;
	req->u.bgp.kni = iface == &cps_conf->net->front
		? cps_conf->front_kni
		: cps_conf->back_kni;
	rte_memcpy(req->u.bgp.pkts, pkts, sizeof(*req->u.bgp.pkts) * num_pkts);

	ret = mb_send_entry(&cps_conf->mailbox, req);
	if (ret < 0) {
		CPS_LOG(ERR, "%s: failed to enqueue message to mailbox\n",
			__func__);
		goto free_pkts;
	}

	return 0;

free_pkts:
	for (i = 0; i < num_pkts; i++)
		rte_pktmbuf_free(pkts[i]);
	return ret;
}

static int
assign_cps_queue_ids(struct cps_config *cps_conf)
{
	int ret;

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
			cps_conf->lcore_id);
		if (ret < 0)
			goto fail;
		cps_conf->rx_queue_front = ret;
	}

	ret = get_queue_id(&cps_conf->net->front, QUEUE_TYPE_TX,
		cps_conf->lcore_id);
	if (ret < 0)
		goto fail;
	cps_conf->tx_queue_front = ret;

	if (cps_conf->net->back_iface_enabled) {
		if (cps_conf->net->back.rss) {
			ret = get_queue_id(&cps_conf->net->back, QUEUE_TYPE_RX,
				cps_conf->lcore_id);
			if (ret < 0)
				goto fail;
			cps_conf->rx_queue_back = ret;
		}

		ret = get_queue_id(&cps_conf->net->back, QUEUE_TYPE_TX,
			cps_conf->lcore_id);
		if (ret < 0)
			goto fail;
		cps_conf->tx_queue_back = ret;
	}

	return 0;

fail:
	CPS_LOG(ERR, "Cannot assign queues\n");
	return ret;
}

/*
 * Many NIC drivers apparently do not directly support the
 * link up/link down functionality of DPDK's Ethernet library.
 * Instead, the suggested way to bring a KNI's link up (shown in
 * the KNI sample application) is to stop and start the device.
 *
 * Starting and stopping a device can make the NIC lose
 * configuration related to RSS and filters, so we need to wait
 * to do any of that configuration until after we are finished
 * restarting the devices.
 *
 * During KNI initialization, the backing device for the KNI
 * must be restarted twice: when the KNI is created and when
 * the link for the KNI is configured to be up.
 *
 * This requires creating the KNI, modifying the KNI's link to
 * be up, and starting the devices to be done in a careful
 * sequential order:
 *
 * Stage 1
 * =======
 *  - Create the KNI(s)
 *  - Modify the link status of the KNI(s) to be up
 *
 * Stage 2
 * =======
 *  - Start the port(s)
 *  - Setup IPv6 addresses
 *  - Individual blocks add IP addresses to the KNI(s),
 *    setup filters, and setup RSS
 *
 * Because of this behavior, warnings on initialization about
 * the devices already being stopped or already being started
 * are expected.
 */
static int
kni_create(struct rte_kni **kni, const char *kni_name, struct rte_mempool *mp,
	struct gatekeeper_if *iface)
{
	struct rte_kni_conf conf;
	struct rte_eth_dev_info dev_info;
	struct rte_kni_ops ops;

	memset(&conf, 0, sizeof(conf));
	RTE_VERIFY(strlen(kni_name) < sizeof(conf.name));
	strcpy(conf.name, kni_name);
	conf.mbuf_size = rte_pktmbuf_data_room_size(mp);

	/* If the interface is bonded, take PCI info from the primary slave. */
	if (iface->num_ports > 1 || iface->bonding_mode == BONDING_MODE_8023AD)
		conf.group_id = rte_eth_bond_primary_get(iface->id);
	else
		conf.group_id = iface->id;

	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(conf.group_id, &dev_info);
	if (dev_info.device != NULL) {
		const struct rte_bus *bus =
			rte_bus_find_by_device(dev_info.device);
		if (bus != NULL && strcmp(bus->name, "pci") == 0) {
			struct rte_pci_device *pci_dev =
				RTE_DEV_TO_PCI(dev_info.device);
			conf.addr = pci_dev->addr;
			conf.id = pci_dev->id;
		} else
			goto nodev;
	} else {
nodev:
		CPS_LOG(ERR,
			"Could not create KNI %s for iface with no dev/PCI data\n",
			conf.name);
		return -1;
	}

	memset(&ops, 0, sizeof(ops));
	ops.port_id = conf.group_id;
	ops.change_mtu = kni_change_mtu;
	ops.config_network_if = kni_change_if;
	ops.config_mac_address = kni_disable_change_mac_address;

	*kni = rte_kni_alloc(mp, &conf, &ops);
	if (*kni == NULL) {
		CPS_LOG(ERR, "Could not allocate KNI for %s iface\n",
			iface->name);
		return -1;
	}

	return 0;
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
				rte_free(entry);
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
				rte_free(entry);
			} else
				entry->stale = true;
		}
	}
}

static int
cps_stage1(void *arg)
{
	struct cps_config *cps_conf = arg;
	unsigned int socket_id = rte_lcore_to_socket_id(cps_conf->lcore_id);
	char name[RTE_KNI_NAMESIZE];
	int ret;

	ret = assign_cps_queue_ids(cps_conf);
	if (ret < 0)
		goto error;

	ret = snprintf(name, sizeof(name), "kni_%s",
		cps_conf->net->front.name);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(name));

	ret = kni_create(&cps_conf->front_kni, name,
		cps_conf->net->gatekeeper_pktmbuf_pool[socket_id],
		&cps_conf->net->front);
	if (ret < 0) {
		CPS_LOG(ERR, "Failed to create KNI for the front iface\n");
		goto error;
	}

	ret = kni_config_link(cps_conf->front_kni);
	if (ret < 0) {
		CPS_LOG(ERR,
			"Failed to configure KNI link on the front iface\n");
		goto error;
	}

	cps_conf->front_kni_index = if_nametoindex(name);
	if (cps_conf->front_kni_index == 0) {
		CPS_LOG(ERR, "Failed to get front KNI index: %s\n",
			strerror(errno));
		goto error;
	}

	if (cps_conf->net->back_iface_enabled) {
		ret = snprintf(name, sizeof(name), "kni_%s",
			cps_conf->net->back.name);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(name));

		ret = kni_create(&cps_conf->back_kni, name,
			cps_conf->net->gatekeeper_pktmbuf_pool[socket_id],
			&cps_conf->net->back);
		if (ret < 0) {
			CPS_LOG(ERR,
				"Failed to create KNI for the back iface\n");
			goto error;
		}

		ret = kni_config_link(cps_conf->back_kni);
		if (ret < 0) {
			CPS_LOG(ERR,
				"Failed to configure KNI link on the back iface\n");
			goto error;
		}

		cps_conf->back_kni_index = if_nametoindex(name);
		if (cps_conf->back_kni_index == 0) {
			CPS_LOG(ERR, "Failed to get back KNI index: %s\n",
				strerror(errno));
			goto error;
		}
	}

	return 0;

error:
	cleanup_cps();
	return ret;
}

static void
fill_bgp4_rule(struct ipv4_acl_rule *rule, struct gatekeeper_if *iface,
	int filter_source_port, uint16_t tcp_port_bgp)
{
	rule->data.category_mask = 0x1;
	rule->data.priority = 1;
	/* Userdata is filled in in register_ipv4_acl(). */

	rule->field[PROTO_FIELD_IPV4].value.u8 = IPPROTO_TCP;
	rule->field[PROTO_FIELD_IPV4].mask_range.u8 = 0xFF;

	rule->field[DST_FIELD_IPV4].value.u32 =
		rte_be_to_cpu_32(iface->ip4_addr.s_addr);
	rule->field[DST_FIELD_IPV4].mask_range.u32 = 32;

	if (filter_source_port) {
		rule->field[SRCP_FIELD_IPV4].value.u16 = tcp_port_bgp;
		rule->field[SRCP_FIELD_IPV4].mask_range.u16 = 0xFFFF;
	} else {
		rule->field[DSTP_FIELD_IPV4].value.u16 = tcp_port_bgp;
		rule->field[DSTP_FIELD_IPV4].mask_range.u16 = 0xFFFF;
	}
}

static void
fill_bgp6_rule(struct ipv6_acl_rule *rule, struct gatekeeper_if *iface,
	int filter_source_port, uint16_t tcp_port_bgp)
{
	uint32_t *ptr32 = (uint32_t *)&iface->ip6_addr.s6_addr;
	int i;

	rule->data.category_mask = 0x1;
	rule->data.priority = 1;
	/* Userdata is filled in in register_ipv6_acl(). */

	rule->field[PROTO_FIELD_IPV6].value.u8 = IPPROTO_TCP;
	rule->field[PROTO_FIELD_IPV6].mask_range.u8 = 0xFF;

	for (i = DST1_FIELD_IPV6; i <= DST4_FIELD_IPV6; i++) {
		rule->field[i].value.u32 = rte_be_to_cpu_32(*ptr32);
		rule->field[i].mask_range.u32 = 32;
		ptr32++;
	}

	if (filter_source_port) {
		rule->field[SRCP_FIELD_IPV6].value.u16 = tcp_port_bgp;
		rule->field[SRCP_FIELD_IPV6].mask_range.u16 = 0xFFFF;
	} else {
		rule->field[DSTP_FIELD_IPV6].value.u16 = tcp_port_bgp;
		rule->field[DSTP_FIELD_IPV6].mask_range.u16 = 0xFFFF;
	}
}

/*
 * Match the packet if it fails to be classifed by ACL rules.
 * If it's a bgp packet, then submit it to the CPS block.
 *
 * Return values: 0 for successful match, and -ENOENT for no matching.
 */
static int
match_bgp4(struct rte_mbuf *pkt, struct gatekeeper_if *iface)
{
	/*
	 * The TCP header offset in terms of the
	 * beginning of the IPv4 header.
	 */
	const uint16_t BE_ETHER_TYPE_IPv4 = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	struct ether_hdr *eth_hdr =
		rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	struct ipv4_hdr *ip4hdr;
	struct tcp_hdr *tcp_hdr;
	uint16_t ether_type_be = pkt_in_skip_l2(pkt, eth_hdr, (void **)&ip4hdr);
	size_t l2_len = pkt_in_l2_hdr_len(pkt);
	uint16_t minimum_size = l2_len +
		sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr);
	uint16_t cps_bgp_port = rte_cpu_to_be_16(get_cps_conf()->tcp_port_bgp);

	if (unlikely(ether_type_be != BE_ETHER_TYPE_IPv4))
		return -ENOENT;

	if (pkt->data_len < minimum_size)
		return -ENOENT;

	if (ip4hdr->dst_addr != iface->ip4_addr.s_addr)
		return -ENOENT;

	if (ip4hdr->next_proto_id != IPPROTO_TCP)
		return -ENOENT;

	minimum_size = l2_len + ipv4_hdr_len(ip4hdr) +
		sizeof(*tcp_hdr);
	if (pkt->data_len < minimum_size)
		return -ENOENT;

	tcp_hdr = (struct tcp_hdr *)ipv4_skip_exthdr(ip4hdr);
	if (tcp_hdr->src_port != cps_bgp_port &&
			tcp_hdr->dst_port != cps_bgp_port)
		return -ENOENT;

	return 0;
}

/*
 * Match the packet if it fails to be classifed by ACL rules.
 * If it's a bgp packet, then submit it to the CPS block.
 *
 * Return values: 0 for successful match, and -ENOENT for no matching.
 */
static int
match_bgp6(struct rte_mbuf *pkt, struct gatekeeper_if *iface)
{
	/*
	 * The TCP header offset in terms of the
	 * beginning of the IPv6 header.
	 */
	int tcp_offset;
	uint8_t nexthdr;
	const uint16_t BE_ETHER_TYPE_IPv6 = rte_cpu_to_be_16(ETHER_TYPE_IPv6);
	struct ether_hdr *eth_hdr =
		rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	struct ipv6_hdr *ip6hdr;
	struct tcp_hdr *tcp_hdr;
	uint16_t ether_type_be = pkt_in_skip_l2(pkt, eth_hdr, (void **)&ip6hdr);
	size_t l2_len = pkt_in_l2_hdr_len(pkt);
	uint16_t minimum_size = l2_len +
		sizeof(struct ipv6_hdr) + sizeof(struct tcp_hdr);
	uint16_t cps_bgp_port = rte_cpu_to_be_16(get_cps_conf()->tcp_port_bgp);

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

	minimum_size += tcp_offset - sizeof(*ip6hdr);
	if (pkt->data_len < minimum_size)
		return -ENOENT;

	tcp_hdr = (struct tcp_hdr *)((uint8_t *)ip6hdr + tcp_offset);
	if (tcp_hdr->src_port != cps_bgp_port &&
			tcp_hdr->dst_port != cps_bgp_port)
		return -ENOENT;

	return 0;
}

static int
add_bgp_filters(struct gatekeeper_if *iface, uint16_t tcp_port_bgp,
	uint16_t rx_queue)
{
	if (ipv4_if_configured(iface)) {
		if (hw_filter_ntuple_available(iface)) {
			/*
			 * Capture pkts for connections
			 * started by our BGP speaker.
			 */
			int ret = ntuple_filter_add(iface,
				iface->ip4_addr.s_addr,
				rte_cpu_to_be_16(tcp_port_bgp), UINT16_MAX,
				0, 0, IPPROTO_TCP, rx_queue, true, false);
			if (ret < 0) {
				CPS_LOG(ERR,
					"Could not add source IPv4 BGP filter on %s iface\n",
					iface->name);
				return ret;
			}

			/* Capture connections remote speakers started. */
			ret = ntuple_filter_add(iface,
				iface->ip4_addr.s_addr, 0, 0,
				rte_cpu_to_be_16(tcp_port_bgp), UINT16_MAX,
				IPPROTO_TCP, rx_queue, true, false);
			if (ret < 0) {
				CPS_LOG(ERR,
					"Could not add destination IPv4 BGP filter on %s iface\n",
					iface->name);
				return ret;
			}
		} else {
			struct ipv4_acl_rule ipv4_rules[NUM_ACL_BGP_RULES];
			int ret;

			memset(&ipv4_rules, 0, sizeof(ipv4_rules));

			/* Capture connections started by our BGP speaker. */
			fill_bgp4_rule(&ipv4_rules[0], iface,
				true, tcp_port_bgp);
			/* Capture connections remote BGP speakers started. */
			fill_bgp4_rule(&ipv4_rules[1], iface,
				false, tcp_port_bgp);

			ret = register_ipv4_acl(ipv4_rules, NUM_ACL_BGP_RULES,
				submit_bgp, match_bgp4, iface);
			if (ret < 0) {
				CPS_LOG(ERR,
					"Could not register BGP IPv4 ACL on %s iface\n",
					iface->name);
				return ret;
			}
		}
	}

	if (ipv6_if_configured(iface)) {
		struct ipv6_acl_rule ipv6_rules[NUM_ACL_BGP_RULES];
		int ret;

		memset(&ipv6_rules, 0, sizeof(ipv6_rules));

		/* Capture pkts for connections started by our BGP speaker. */
		fill_bgp6_rule(&ipv6_rules[0], iface, true, tcp_port_bgp);
		/* Capture pkts for connections remote BGP speakers started. */
		fill_bgp6_rule(&ipv6_rules[1], iface, false, tcp_port_bgp);

		ret = register_ipv6_acl(ipv6_rules, NUM_ACL_BGP_RULES,
			submit_bgp, match_bgp6, iface);
		if (ret < 0) {
			CPS_LOG(ERR,
				"Could not register BGP IPv6 ACL on %s iface\n",
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

	ret = add_bgp_filters(&cps_conf->net->front,
		cps_conf->tcp_port_bgp, cps_conf->rx_queue_front);
	if (ret < 0) {
		CPS_LOG(ERR, "Failed to add BGP filters on the front iface");
		goto error;
	}

	ret = kni_config_ip_addrs(cps_conf->front_kni,
		cps_conf->front_kni_index, &cps_conf->net->front);
	if (ret < 0) {
		CPS_LOG(ERR, "Failed to configure KNI IP addresses on the front iface\n");
		goto error;
	}

	if (cps_conf->net->back_iface_enabled) {
		ret = add_bgp_filters(&cps_conf->net->back,
			cps_conf->tcp_port_bgp, cps_conf->rx_queue_back);
		if (ret < 0) {
			CPS_LOG(ERR, "Failed to add BGP filters on the back iface");
			goto error;
		}

		ret = kni_config_ip_addrs(cps_conf->back_kni,
			cps_conf->back_kni_index, &cps_conf->net->back);
		if (ret < 0) {
			CPS_LOG(ERR, "Failed to configure KNI IP addresses on the back iface\n");
			goto error;
		}
	}

	ret = rd_event_sock_open(cps_conf);
	if (ret < 0) {
		CPS_LOG(ERR, "Failed to open routing daemon event socket\n");
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
	struct lls_config *lls_conf, const char *kni_kmod_path)
{
	int ret;
	int ele_size;
	uint16_t front_inc, back_inc = 0;

	if (net_conf == NULL || (gk_conf == NULL && gt_conf == NULL) ||
			cps_conf == NULL || lls_conf == NULL) {
		ret = -1;
		goto out;
	}

	cps_logtype = rte_log_register("gatekeeper.cps");
	if (cps_logtype < 0) {
		ret = -1;
		goto out;
	}
	ret = rte_log_set_level(cps_logtype, cps_conf->log_level);
	if (ret < 0) {
		ret = -1;
		goto out;
	}
	cps_conf->log_type = cps_logtype;

	log_ratelimit_state_init(cps_conf->lcore_id,
		cps_conf->log_ratelimit_interval_ms,
		cps_conf->log_ratelimit_burst);

	/* Take the packets needed in the KNI into account as well. */
	front_inc = 2 * cps_conf->front_max_pkt_burst;
	net_conf->front.total_pkt_burst += front_inc;
	if (net_conf->back_iface_enabled) {
		back_inc = 2 * cps_conf->back_max_pkt_burst;
		net_conf->back.total_pkt_burst += back_inc;
	}

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
		CPS_LOG(ERR, "Option nl_pid must be greater than 0\n");
		goto stage3;
	}

	ret = init_kni(kni_kmod_path, net_conf->back_iface_enabled ? 2 : 1);
	if (ret < 0) {
		CPS_LOG(ERR, "Couldn't initialize KNI\n");
		goto stage3;
	}

	if (gk_conf != NULL) {
		cps_conf->mailbox_max_pkt_burst =
			RTE_MAX(gk_conf->front_max_pkt_burst,
				gk_conf->back_max_pkt_burst);
	}

	if (gt_conf != NULL) {
		cps_conf->mailbox_max_pkt_burst =
			RTE_MAX(cps_conf->mailbox_max_pkt_burst,
				gt_conf->gt_max_pkt_burst);
	}

	ele_size = RTE_MAX(sizeof(struct cps_request),
		offsetof(struct cps_request, end_of_header) +
		sizeof(struct cps_bgp_req) + sizeof(struct rte_mbuf *) *
		cps_conf->mailbox_max_pkt_burst);

	ret = init_mailbox("cps_mb", cps_conf->mailbox_max_entries_exp,
		ele_size, cps_conf->mailbox_mem_cache_size,
		cps_conf->lcore_id, &cps_conf->mailbox);
	if (ret < 0)
		goto kni;

	if (arp_enabled(cps_conf->lls))
		INIT_LIST_HEAD(&cps_conf->arp_requests);
	if (nd_enabled(cps_conf->lls))
		INIT_LIST_HEAD(&cps_conf->nd_requests);

	rte_timer_init(&cps_conf->scan_timer);
	ret = rte_timer_reset(&cps_conf->scan_timer,
		cps_conf->scan_interval_sec * rte_get_timer_hz(),
		PERIODICAL, cps_conf->lcore_id, cps_scan, cps_conf);
	if (ret < 0) {
		CPS_LOG(ERR, "Cannot set CPS scan timer\n");
		goto mailbox;
	}

	if (gk_conf != NULL)
		gk_conf_hold(gk_conf);
	cps_conf->gk = gk_conf;

	if (gt_conf != NULL)
		gt_conf_hold(gt_conf);
	cps_conf->gt = gt_conf;

	return 0;
mailbox:
	destroy_mailbox(&cps_conf->mailbox);
kni:
	rm_kni();
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
