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

#ifndef _GATEKEEPER_GK_H_
#define _GATEKEEPER_GK_H_

#include <rte_atomic.h>

#include "gatekeeper_ipip.h"
#include "gatekeeper_ggu.h"
#include "gatekeeper_mailbox.h"

/*
 * A flow entry can be in one of three states:
 * request, granted, or declined.
 */
enum gk_flow_state { GK_REQUEST, GK_GRANTED, GK_DECLINED };

/* Structures for each GK instance. */
struct gk_instance {
	struct rte_hash   *ip_flow_hash_table;
	struct flow_entry *ip_flow_entry_table;
	/* RX queue on the front interface. */
	uint16_t          rx_queue_front;
	/* TX queue on the back interface. */
	uint16_t          tx_queue_back;
	struct mailbox    mb; 
};

/* Configuration for the GK functional block. */
struct gk_config {
	/*
  	 * XXX The lcore IDs may not be sequential (e.g. only odd numbers).
  	 * We need an array of lcores to use.
  	 */
	unsigned int	   lcore_start_id;
	unsigned int	   lcore_end_id;

	/* Specify the size of the flow hash table. */
	unsigned int	   flow_ht_size;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */
	rte_atomic32_t	   ref_cnt;
	struct gk_instance *instances;
	struct net_config  *net;
	struct gatekeeper_rss_config rss_conf;
};

/* Define the possible command operations for GK block. */
enum gk_cmd_op { GGU_POLICY_ADD, };

/*
 * XXX Structure for each command. Add new fields to support more commands.
 *
 * Notice that, the writers of a GK mailbox: the GK-GT unit and Dynamic config.
 */
struct gk_cmd_entry {
	enum gk_cmd_op  op;

	union {
		struct ggu_policy ggu;
	} u;
};

struct gk_config *alloc_gk_conf(void);
int gk_conf_put(struct gk_config *gk_conf);
int run_gk(struct net_config *net_conf, struct gk_config *gk_conf);
int cleanup_gk(struct gk_config *gk_conf);
struct mailbox *get_responsible_gk_mailbox(
	const struct ip_flow *flow, const struct gk_config *gk_conf);

static inline void
gk_conf_hold(struct gk_config *gk_conf)
{
	rte_atomic32_inc(&gk_conf->ref_cnt);
}

#endif /* _GATEKEEPER_GK_H_ */
