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

#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include "gatekeeper_gt.h"
#include "gatekeeper_main.h"
#include "gatekeeper_net.h"
#include "gatekeeper_launch.h"

static int
get_block_idx(struct gt_config *gt_conf, unsigned int lcore_id)
{
	int i;
	for (i = 0; i < gt_conf->num_lcores; i++)
		if (gt_conf->lcores[i] == lcore_id)
			return i;
	rte_panic("Unexpected condition: lcore %u is not running a gt block\n",
		lcore_id);
	return 0;
}

static int
gt_setup_rss(struct gt_config *gt_conf)
{
	int i;
	uint8_t port_in = gt_conf->net->front.id;
	uint16_t gt_queues[gt_conf->num_lcores];

	for (i = 0; i < gt_conf->num_lcores; i++)
		gt_queues[i] = gt_conf->instances[i].rx_queue;

	return gatekeeper_setup_rss(port_in, gt_queues, gt_conf->num_lcores);
}

static int
gt_proc(void *arg)
{
	unsigned int lcore = rte_lcore_id();
	struct gt_config *gt_conf = (struct gt_config *)arg;
	unsigned int block_idx = get_block_idx(gt_conf, lcore);
	struct gt_instance *instance = &gt_conf->instances[block_idx];

	uint8_t port = get_net_conf()->front.id;
	uint16_t rx_queue = instance->rx_queue;
	uint16_t tx_queue = instance->tx_queue;

	RTE_LOG(NOTICE, GATEKEEPER,
		"gt: the GT block is running at lcore = %u\n", lcore);

	gt_conf_hold(gt_conf);

	while (likely(!exiting)) {
		int i;
		uint16_t num_rx;
		uint16_t num_tx_succ;
		struct rte_mbuf *rx_bufs[GATEKEEPER_MAX_PKT_BURST];

		/* Load a set of packets from the front NIC. */
		num_rx = rte_eth_rx_burst(port, rx_queue, rx_bufs,
			GATEKEEPER_MAX_PKT_BURST);

		if (unlikely(num_rx == 0))
			continue;

		for (i = 0; i < num_rx; i++) {
			/*
			 * TODO Decapsulate the packets.
			 *
			 * Only request packets and priority packets
			 * with capabilities about to expire go through a
			 * policy decision.
			 *
			 * Other packets will be fowarded directly.
			 */

			/*
			 * TODO Lookup the policy decision.
			 *
			 * The policy, which is defined by a Lua script,
			 * decides which capabilities to grant or decline,
			 * the maximum receiving rate of the granted
			 * capabilities, and when each decision expires.
			 */

			/* TODO Reply the policy decision to GK-GT unit. */
		}

		/* Send burst of TX packets, to second port of pair. */
		num_tx_succ = rte_eth_tx_burst(port, tx_queue,
			rx_bufs, num_rx);

		/*
		 * XXX Do something better here!
		 * For now, free any unsent packets.
		 */
		if (unlikely(num_tx_succ < num_rx)) {
			for (i = num_tx_succ; i < num_rx; i++)
				rte_pktmbuf_free(rx_bufs[i]);
		}
	}

	RTE_LOG(NOTICE, GATEKEEPER,
		"gt: the GT block at lcore = %u is exiting\n", lcore);

	return gt_conf_put(gt_conf);
}

struct gt_config *
alloc_gt_conf(void)
{
	return rte_calloc("gt_config", 1, sizeof(struct gt_config), 0);
}

static int
cleanup_gt(struct gt_config *gt_conf)
{
	rte_free(gt_conf->instances);
	rte_free(gt_conf->lcores);
	rte_free(gt_conf);

	return 0;
}

int
gt_conf_put(struct gt_config *gt_conf)
{
	/*
	 * Atomically decrements the atomic counter (v) by one and returns true 
	 * if the result is 0, or false in all other cases.
	 */
	if (rte_atomic32_dec_and_test(&gt_conf->ref_cnt))
		return cleanup_gt(gt_conf);

	return 0;
}

static int
init_gt_instances(struct gt_config *gt_conf)
{
	int i;
	int ret;

	/* Set up queue identifiers now for RSS, before instances start. */
	for (i = 0; i < gt_conf->num_lcores; i++) {
		unsigned int lcore = gt_conf->lcores[i];
		struct gt_instance *inst_ptr = &gt_conf->instances[i];

		ret = get_queue_id(&gt_conf->net->front, QUEUE_TYPE_RX, lcore);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER, "gt: cannot assign an RX queue for the front interface for lcore %u\n",
				lcore);
			goto out;
		}
		inst_ptr->rx_queue = ret;

		ret = get_queue_id(&gt_conf->net->front, QUEUE_TYPE_TX, lcore);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER, "gt: cannot assign a TX queue for the front interface for lcore %u\n",
				lcore);
			goto out;
		}
		inst_ptr->tx_queue = ret;
	}

	ret = 0;

out:
	return ret;
}

static int
gt_stage1(void *arg)
{
	int ret;
	struct gt_config *gt_conf = arg;

	gt_conf->instances = rte_calloc(__func__, gt_conf->num_lcores,
		sizeof(struct gt_instance), 0);
	if (gt_conf->instances == NULL) {
		ret = -1;
		goto out;
	}

	ret = init_gt_instances(gt_conf);
	if (ret < 0)
		goto  instance;

	goto out;

instance:
	rte_free(gt_conf->instances);
	gt_conf->instances = NULL;
	rte_free(gt_conf->lcores);
	gt_conf->lcores = NULL;
out:
	return ret;
}

static int
gt_stage2(void *arg)
{
	struct gt_config *gt_conf = arg;
	return gt_setup_rss(gt_conf);
}

int
run_gt(struct net_config *net_conf, struct gt_config *gt_conf)
{
	int ret, i;

	if (net_conf == NULL || gt_conf == NULL) {
		ret = -1;
		goto out;
	}

	gt_conf->net = net_conf;

	if (gt_conf->num_lcores <= 0)
		goto success;

	ret = net_launch_at_stage1(net_conf, gt_conf->num_lcores,
		gt_conf->num_lcores, 0, 0, gt_stage1, gt_conf);
	if (ret < 0)
		goto out;

	ret = launch_at_stage2(gt_stage2, gt_conf);
	if (ret < 0)
		goto stage1;

	for (i = 0; i < gt_conf->num_lcores; i++) {
		unsigned int lcore = gt_conf->lcores[i];
		ret = launch_at_stage3("gt", gt_proc, gt_conf, lcore);
		if (ret < 0) {
			pop_n_at_stage3(i);
			goto stage2;
		}
	}

	goto success;

stage2:
	pop_n_at_stage2(1);
stage1:
	pop_n_at_stage1(1);
out:
	return ret;

success:
	rte_atomic32_init(&gt_conf->ref_cnt);
	return 0;
}
