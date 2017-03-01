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

#include "gatekeeper_acl.h"
#include "gatekeeper_cps.h"
#include "gatekeeper_launch.h"
#include "kni.h"

/*
 * To capture BGP packets with source port 179 or destination port 179
 * on a global IPv6 address, we need two rules (per interface).
 */
#define NUM_ACL_BGP_RULES (2)

/* XXX Sample parameters, need to be tested for better performance. */
#define CPS_REQ_BURST_SIZE (32)

/* Information needed to submit IPv6 BGP packets to the CPS block. */
struct cps_bgp_req {
	/* IPv6 BGP packets. */
	struct rte_mbuf      *pkts[GATEKEEPER_MAX_PKT_BURST];

	/* Number of packets stored in @pkts. */
	unsigned int         num_pkts;

	/* KNI that should receive @pkts. */
	struct rte_kni       *kni;
};

/* Requests that can be made to the CPS block. */
enum cps_req_ty {
	/* Request to handle an IPv6 BGP packet received from another block. */
	CPS_REQ_BGP,
};

/* Request submitted to the CPS block. */
struct cps_request {
	/* Type of request. */
	enum cps_req_ty ty;

	union {
		/* If @ty is CPS_REQ_BGP, use @bgp. */
		struct cps_bgp_req bgp;
	} u;
};

static struct cps_config cps_conf;

struct cps_config *
get_cps_conf(void)
{
	return &cps_conf;
}

static int
cleanup_cps(void)
{
	/* rte_kni_release() can be passed NULL. */
	rte_kni_release(cps_conf.back_kni);
	rte_kni_release(cps_conf.front_kni);
	destroy_mailbox(&cps_conf.mailbox);
	rm_kni();
	return 0;
}

static void
process_reqs(struct cps_config *cps_conf)
{
	struct cps_request *reqs[CPS_REQ_BURST_SIZE];
	unsigned int count = mb_dequeue_burst(&cps_conf->mailbox,
		(void **)reqs, CPS_REQ_BURST_SIZE);
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
		default:
			RTE_LOG(ERR, GATEKEEPER,
				"cps: unrecognized request type (%d)\n",
				reqs[i]->ty);
			break;
		}
		mb_free_entry(&cps_conf->mailbox, reqs[i]);
	}
}

static void
process_ingress(struct gatekeeper_if *iface, struct rte_kni *kni,
	uint16_t rx_queue)
{
	struct rte_mbuf *bufs[GATEKEEPER_MAX_PKT_BURST];
	uint16_t num_rx = rte_eth_rx_burst(iface->id, rx_queue, bufs,
		GATEKEEPER_MAX_PKT_BURST);
	unsigned int num_tx = rte_kni_tx_burst(kni, bufs, num_rx);

	if (unlikely(num_tx < num_rx)) {
		uint16_t i;
		for (i = num_tx; i < num_rx; i++)
			rte_pktmbuf_free(bufs[i]);
	}

	/*
	 * Userspace requests to change the device MTU or configure the
	 * device up/down are forwarded from the kernel back to userspace
	 * for DPDK to handle. rte_kni_handle_request() receives those
	 * requests and allows them to be processed.
	 */
	if (rte_kni_handle_request(kni) < 0)
		RTE_LOG(WARNING, KNI,
			"%s: error in handling userspace request on KNI %s\n",
			__func__, rte_kni_get_name(kni));
}

static void
process_egress(struct gatekeeper_if *iface, struct rte_kni *kni,
	uint16_t tx_queue)
{
	struct rte_mbuf *bufs[GATEKEEPER_MAX_PKT_BURST];
	uint16_t num_rx = rte_kni_rx_burst(kni, bufs, GATEKEEPER_MAX_PKT_BURST);
	unsigned int num_tx = rte_eth_tx_burst(iface->id, tx_queue,
		bufs, num_rx);

	/*
	 * TODO Forward BGP, respond to ARP or ND requests with resolution,
	 * and drop everything else.
	 */

	if (unlikely(num_tx < num_rx)) {
		uint16_t i;
		for (i = num_tx; i < num_rx; i++)
			rte_pktmbuf_free(bufs[i]);
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

	RTE_LOG(NOTICE, GATEKEEPER,
		"cps: the CPS block is running at lcore = %u\n",
		cps_conf->lcore_id);

	while (likely(!exiting)) {
		/*
		 * Read in IPv4 BGP packets that arrive directly
		 * on the Gatekeeper interfaces.
		 */
		process_ingress(front_iface, front_kni,
			cps_conf->rx_queue_front);
		if (net_conf->back_iface_enabled)
			process_ingress(back_iface, back_kni,
				cps_conf->rx_queue_back);

		/*
		 * Process any requests made to the CPS block, including
		 * IPv6 BGP packets that arrived via an ACL.
		 */
		process_reqs(cps_conf);

		/*
		 * Read in packets from KNI interfaces, and
		 * transmit to respective Gatekeeper interfaces.
		 */
		process_egress(front_iface, front_kni,
			cps_conf->tx_queue_front);
		if (net_conf->back_iface_enabled)
			process_egress(back_iface, back_kni,
				cps_conf->tx_queue_back);

		/* TODO Get route updates from kernel. */
	}

	RTE_LOG(NOTICE, GATEKEEPER,
		"cps: the CPS block at lcore = %u is exiting\n",
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

	RTE_VERIFY(num_pkts <=
		(sizeof(req->u.bgp.pkts) / sizeof(*req->u.bgp.pkts)));

	if (req == NULL) {
		RTE_LOG(ERR, GATEKEEPER,
			"cps: %s: allocation of mailbox message failed\n",
			__func__);
		return -1;
	}

	req->ty = CPS_REQ_BGP;
	req->u.bgp.num_pkts = num_pkts;
	req->u.bgp.kni = iface == &cps_conf->net->front
		? cps_conf->front_kni
		: cps_conf->back_kni;
	rte_memcpy(req->u.bgp.pkts, pkts, sizeof(*req->u.bgp.pkts) * num_pkts);

	ret = mb_send_entry(&cps_conf->mailbox, req);
	if (ret < 0) {
		unsigned int i;
		RTE_LOG(ERR, GATEKEEPER,
			"cps: %s: failed to enqueue message to mailbox\n",
			__func__);
		for (i = 0; i < num_pkts; i++)
			rte_pktmbuf_free(pkts[i]);
		return ret;
	}

	return 0;
}

static int
assign_cps_queue_ids(struct cps_config *cps_conf)
{
	int ret = get_queue_id(&cps_conf->net->front, QUEUE_TYPE_RX,
		cps_conf->lcore_id);
	if (ret < 0)
		goto fail;
	cps_conf->rx_queue_front = ret;

	ret = get_queue_id(&cps_conf->net->front, QUEUE_TYPE_TX,
		cps_conf->lcore_id);
	if (ret < 0)
		goto fail;
	cps_conf->tx_queue_front = ret;

	if (cps_conf->net->back_iface_enabled) {
		ret = get_queue_id(&cps_conf->net->back, QUEUE_TYPE_RX,
			cps_conf->lcore_id);
		if (ret < 0)
			goto fail;
		cps_conf->rx_queue_back = ret;

		ret = get_queue_id(&cps_conf->net->back, QUEUE_TYPE_TX,
			cps_conf->lcore_id);
		if (ret < 0)
			goto fail;
		cps_conf->tx_queue_back = ret;
	}

	return 0;

fail:
	RTE_LOG(ERR, GATEKEEPER, "cps: cannot assign queues\n");
	return ret;
}

/*
 * We create the KNIs in stage 1 because creating a KNI seems to
 * restart the PCI device on which the KNI is based, which removes
 * some (but not all) device-specific configuration that has already
 * happened (RETA, multicast Ethernet addresses, etc). Therefore, if
 * we put the KNI creation in stage 2 (after the devices are started),
 * we will have to re-do some of the configuration.
 *
 * Following the documentation strictly, the call to
 * rte_eth_dev_info_get() here should take place *after* the NIC is
 * started. However, this rule is widely broken throughout DPDK, and
 * breaking it here makes configuration much easier due to this
 * problem of restarting the devices. 
 */
static int
kni_create(struct rte_kni **kni, struct rte_mempool *mp,
	struct gatekeeper_if *iface)
{
	struct rte_kni_conf conf;
	struct rte_eth_dev_info dev_info;
	struct rte_kni_ops ops;
	int ret;

	memset(&conf, 0, sizeof(conf));
	ret = snprintf(conf.name, RTE_KNI_NAMESIZE, "kni_%s", iface->name);
	RTE_VERIFY(ret > 0 && ret < RTE_KNI_NAMESIZE);
	conf.mbuf_size = rte_pktmbuf_data_room_size(mp);

	/* If the interface is bonded, take PCI info from the primary slave. */
	if (iface->num_ports > 1 || iface->bonding_mode == BONDING_MODE_8023AD)
		conf.group_id = rte_eth_bond_primary_get(iface->id);
	else
		conf.group_id = iface->id;
	rte_eth_dev_info_get(conf.group_id, &dev_info);
	conf.addr = dev_info.pci_dev->addr;
	conf.id = dev_info.pci_dev->id;

	memset(&ops, 0, sizeof(ops));
	ops.port_id = conf.group_id;
	ops.change_mtu = kni_change_mtu;
	ops.config_network_if = kni_change_if;

	*kni = rte_kni_alloc(mp, &conf, &ops);
	if (*kni == NULL) {
		RTE_LOG(ERR, KNI, "Could not allocate KNI for %s iface\n",
			iface->name);
		return -1;
	}

	return 0;
}

static int
cps_stage1(void *arg)
{
	struct cps_config *cps_conf = arg;
	unsigned int socket_id = rte_lcore_to_socket_id(cps_conf->lcore_id);
	int ret;

	ret = assign_cps_queue_ids(cps_conf);
	if (ret < 0)
		goto error;

	ret = kni_create(&cps_conf->front_kni,
		cps_conf->net->gatekeeper_pktmbuf_pool[socket_id],
		&cps_conf->net->front);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"cps: failed to create KNI for the front iface\n");
		goto error;
	}

	if (cps_conf->net->back_iface_enabled) {
		ret = kni_create(&cps_conf->back_kni,
			cps_conf->net->gatekeeper_pktmbuf_pool[socket_id],
			&cps_conf->net->back);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER,
				"cps: failed to create KNI for the back iface\n");
			goto error;
		}
	}

	return 0;

error:
	cleanup_cps();
	return ret;
}

static void
fill_bgp_rule(struct ipv6_acl_rule *rule, struct gatekeeper_if *iface,
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

static int
add_bgp_filters(struct gatekeeper_if *iface, uint16_t tcp_port_bgp,
	uint16_t rx_queue)
{
	if (ipv4_if_configured(iface)) {
		int ret;
		/* Capture pkts for connections started by our BGP speaker. */
		ret = ntuple_filter_add(iface->id, iface->ip4_addr.s_addr,
			rte_cpu_to_be_16(tcp_port_bgp), UINT16_MAX, 0, 0,
			IPPROTO_TCP, rx_queue, true);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER,
				"cps: could not add source BGP filter on %s iface\n",
				iface->name);
			return ret;
		}
		/* Capture pkts for connections remote BGP speakers started. */
		ret = ntuple_filter_add(iface->id, iface->ip4_addr.s_addr,
			0, 0, rte_cpu_to_be_16(tcp_port_bgp), UINT16_MAX,
			IPPROTO_TCP, rx_queue, true);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER,
				"cps: could not add destination BGP filter on %s iface\n",
				iface->name);
			return ret;
		}
	}

	if (ipv6_if_configured(iface)) {
		struct ipv6_acl_rule ipv6_rules[NUM_ACL_BGP_RULES];
		int ret;

		memset(&ipv6_rules, 0, sizeof(ipv6_rules));

		/* Capture pkts for connections started by our BGP speaker. */
		fill_bgp_rule(&ipv6_rules[0], iface, true, tcp_port_bgp);
		/* Capture pkts for connections remote BGP speakers started. */
		fill_bgp_rule(&ipv6_rules[1], iface, false, tcp_port_bgp);

		ret = register_ipv6_acl(ipv6_rules, NUM_ACL_BGP_RULES,
			submit_bgp, iface);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER,
				"cps: could not register BGP IPv6 ACL on %s iface\n",
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
		RTE_LOG(ERR, GATEKEEPER,
			"cps: failed to add BGP filters on the front iface");
		goto error;
	}

	ret = kni_config(cps_conf->front_kni, &cps_conf->net->front);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"cps: failed to configure KNI on the front iface\n");
		goto error;
	}

	if (cps_conf->net->back_iface_enabled) {
		ret = add_bgp_filters(&cps_conf->net->back,
			cps_conf->tcp_port_bgp, cps_conf->rx_queue_back);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER,
				"cps: failed to add BGP filters on the back iface");
			goto error;
		}

		ret = kni_config(cps_conf->back_kni, &cps_conf->net->back);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER,
				"cps: failed to configure KNI on the back iface\n");
			goto error;
		}
	}

	return 0;

error:
	cleanup_cps();
	return ret;
}

int
run_cps(struct net_config *net_conf, struct cps_config *cps_conf,
	const char *kni_kmod_path)
{
	int ret;

	if (net_conf == NULL || cps_conf == NULL) {
		ret = -1;
		goto out;
	}

	ret = net_launch_at_stage1(net_conf, 1, 1, 1, 1, cps_stage1, cps_conf);
	if (ret < 0)
		goto out;

	ret = launch_at_stage2(cps_stage2, cps_conf);
	if (ret < 0)
		goto stage1;

	ret = launch_at_stage3("cps", cps_proc, cps_conf, cps_conf->lcore_id);
	if (ret < 0)
		goto stage2;

	cps_conf->net = net_conf;

	ret = init_kni(kni_kmod_path, net_conf->back_iface_enabled ? 2 : 1);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER, "cps: couldn't initialize KNI\n");
		goto stage3;
	}

	ret = init_mailbox("cps_mb", MAILBOX_MAX_ENTRIES,
		sizeof(struct cps_request), cps_conf->lcore_id,
		&cps_conf->mailbox);
	if (ret < 0)
		goto kni;

	return 0;
kni:
	rm_kni();
stage3:
	pop_n_at_stage3(1);
stage2:
	pop_n_at_stage2(1);
stage1:
	pop_n_at_stage1(1);
out:
	return ret;
}
