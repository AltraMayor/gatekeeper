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

/*
 * This BPF program limits traffic with two rate limits:
 * primary and secondary limits or channels.
 * All traffic is subject to the primary limit.
 * Traffic that fits the primary limit, but is not desirable
 * (e.g. fragmented packets) is subject to the second limit.
 */

#include <arpa/inet.h>

#include "grantedv2.h"

SEC("init") uint64_t
grantedv2_init(struct gk_bpf_init_ctx *ctx)
{
	return grantedv2_init_inline(ctx);
}

SEC("pkt") uint64_t
grantedv2_pkt(struct gk_bpf_pkt_ctx *ctx)
{
	struct grantedv2_state *state =
		(struct grantedv2_state *)pkt_ctx_to_cookie(ctx);
	uint32_t pkt_len = pkt_ctx_to_pkt(ctx)->pkt_len;
	uint64_t ret = grantedv2_pkt_begin(ctx, state, pkt_len);

	if (ret != GK_BPF_PKT_RET_FORWARD)
		return ret;

	if (ctx->fragmented || (ctx->l4_proto != IPPROTO_UDP &&
			ctx->l4_proto != IPPROTO_TCP)) {
		/* Secondary budget. */
		ret = grantedv2_pkt_test_2nd_limit(state, pkt_len);
		if (ret != GK_BPF_PKT_RET_FORWARD)
			return ret;
	}

	return grantedv2_pkt_end(ctx, state);
}
