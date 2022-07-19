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

/* This BPF program mimics the state GK_DECLINED of a flow entry. */

#include <stdint.h>

#include "gatekeeper_flow_bpf.h"

SEC("init") uint64_t
declined_init(struct gk_bpf_init_ctx *ctx)
{
	return GK_BPF_INIT_RET_OK;
}

SEC("pkt") uint64_t
declined_pkt(struct gk_bpf_pkt_ctx *ctx)
{
	return GK_BPF_PKT_RET_DECLINE;
}
