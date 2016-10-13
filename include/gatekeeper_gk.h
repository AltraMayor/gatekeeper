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

/* Structures for each GK instance. */
struct gk_instance {
	struct rte_hash   *ip_flow_hash_table;
	struct flow_entry *ip_flow_entry_table;
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
};

struct gk_config *alloc_gk_conf(void);
int run_gk(struct gk_config *gk_conf);
int cleanup_gk(struct gk_config *gk_conf);

#endif /* _GATEKEEPER_GK_H_ */
