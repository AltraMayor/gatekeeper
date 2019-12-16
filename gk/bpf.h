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

#ifndef _GATEKEEPER_GK_BPF_H_
#define _GATEKEEPER_GK_BPF_H_

#include "gatekeeper_gk.h"
#include "co.h"

/*
 * Load the BPF program that handles flows into @gk_conf at
 * position @index.
 *
 * RETURN
 * 	Zero on success;
 * 	Negative on failure.
 */
int gk_load_bpf_flow_handler(struct gk_config *gk_conf, unsigned int index,
	const char *filename, int jit);

int gk_bpf_decide_pkt(struct gk_co *this_co, uint8_t program_index,
	struct flow_entry *fe, struct ipacket *packet, uint64_t now,
	uint64_t *p_bpf_ret);

#endif /* _GATEKEEPER_GK_BPF_H_ */
