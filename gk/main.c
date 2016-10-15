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

#include <rte_ethdev.h>
#include <rte_malloc.h>

#include "gatekeeper_gk.h"
#include "gatekeeper_main.h"
#include "gatekeeper_net.h"

#define GATEKEEPER_MAX_PKT_BURST (32)

static int
gk_proc(void *arg)
{
	/* TODO Implement the basic algorithm of a GK block. */

	uint32_t lcore = rte_lcore_id();
	struct gk_config *gk_conf = (struct gk_config *)arg;

	uint8_t port_in = get_net_conf()->front.id;
	uint8_t port_out = get_net_conf()->back.id;

	RTE_LOG(NOTICE, GATEKEEPER,
		"gk: the GK block is running at lcore = %u\n", lcore);

	rte_atomic32_inc(&gk_conf->ref_cnt);

	while (likely(!exiting)) {
		/* 
		 * XXX Sample setting for test only.
		 * 
		 * Here, just use one queue (0) for test.
		 *
		 * Queue identifiers should be changed 
		 * according to configuration.
		 */

		/* Get burst of RX packets, from first port of pair. */
		uint16_t num_rx;
		uint16_t num_tx;
		struct rte_mbuf *bufs[GATEKEEPER_MAX_PKT_BURST];

		num_rx = rte_eth_rx_burst(port_in, 0, bufs,
			GATEKEEPER_MAX_PKT_BURST);

		if (unlikely(num_rx == 0))
			continue;

		/* Send burst of TX packets, to second port of pair. */
		num_tx = rte_eth_tx_burst(port_out, 0, bufs, num_rx);

		/* Free any unsent packets. */
		if (unlikely(num_tx < num_rx)) {
			int i;
			for (i = num_tx; i < num_rx; i++)
				rte_pktmbuf_free(bufs[i]);
		}
	}

	RTE_LOG(NOTICE, GATEKEEPER,
		"gk: the GK block at lcore = %u is exiting\n", lcore);

	return cleanup_gk(gk_conf);
}

struct gk_config *
alloc_gk_conf(void)
{
	return rte_calloc("gk_config", 1, sizeof(struct gk_config), 0);
}

int
run_gk(struct gk_config *gk_conf)
{
	/* TODO Initialize and run GK functional block. */

	unsigned int i;
	int ret;

	if (!gk_conf)
		return -1;

	for (i = gk_conf->lcore_start_id; i <= gk_conf->lcore_end_id; i++) {
		ret = rte_eal_remote_launch(gk_proc, gk_conf, i);
		if (ret) {
			RTE_LOG(ERR, EAL, "lcore %u failed to launch GK\n", i);
			return ret;
		}
	}

	return 0;
}

int
cleanup_gk(struct gk_config *gk_conf)
{
	/*
	 * Atomically decrements the atomic counter (v) by one and returns true 
	 * if the result is 0, or false in all other cases.
	 */
	if (rte_atomic32_dec_and_test(&gk_conf->ref_cnt)) {
		rte_free(gk_conf);
	}

	return 0;
}
