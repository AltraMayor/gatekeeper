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
 * This BPF program mimics the state GK_GRANTED of a flow entry.
 * This program example is useful to use as a starting point to write
 * more complex programs that need to limit the bandwidth of a flow.
 */

#include <stdint.h>
#include <stdbool.h>

#include <rte_common.h>

#include "gatekeeper_flow_bpf.h"
#include "bpf_mbuf.h"

struct granted_params {
	/* Rate limit: kibibyte/second. */
	uint32_t tx_rate_kib_sec;
	/*
	 * The first value of send_next_renewal_at at
	 * flow entry comes from next_renewal_ms.
	 */
	uint32_t next_renewal_ms;
	/*
	 * How many milliseconds (unit) GK must wait
	 * before sending the next capability renewal
	 * request.
	 */
	uint32_t renewal_step_ms;
};

struct granted_state {
	/* When @budget_byte is reset. */
	uint64_t budget_renew_at;
	/*
	 * When @budget_byte is reset, reset it to
	 * @tx_rate_kib_cycle * 1024 bytes.
	 */
	uint32_t tx_rate_kib_cycle;
	/* How many bytes @src can still send in current cycle. */
	uint64_t budget_byte;
	/*
	 * When GK should send the next renewal to
	 * the corresponding grantor.
	 */
	uint64_t send_next_renewal_at;
	/*
	 * How many cycles (unit) GK must wait before
	 * sending the next capability renewal request.
	 */
	uint64_t renewal_step_cycle;
};

SEC("init") uint64_t
granted_init(struct gk_bpf_init_ctx *ctx)
{
	struct gk_bpf_cookie *cookie = init_ctx_to_cookie(ctx);
	struct granted_params params = *(struct granted_params *)cookie;
	struct granted_state *state = (struct granted_state *)cookie;

	RTE_BUILD_BUG_ON(sizeof(params) > sizeof(*cookie));
	RTE_BUILD_BUG_ON(sizeof(*state) > sizeof(*cookie));

	state->budget_renew_at = ctx->now + cycles_per_sec;
	state->tx_rate_kib_cycle = params.tx_rate_kib_sec;
	state->budget_byte = (uint64_t)params.tx_rate_kib_sec * 1024;
	state->send_next_renewal_at = ctx->now +
		params.next_renewal_ms * cycles_per_ms;
	state->renewal_step_cycle = params.renewal_step_ms * cycles_per_ms;

	return GK_BPF_INIT_RET_OK;
}

SEC("pkt") uint64_t
granted_pkt(struct gk_bpf_pkt_ctx *ctx)
{
	struct granted_state *state =
		(struct granted_state *)pkt_ctx_to_cookie(ctx);
	uint32_t pkt_len;
	uint8_t priority = PRIORITY_GRANTED;

	if (ctx->now >= state->budget_renew_at) {
		state->budget_renew_at = ctx->now + cycles_per_sec;
		state->budget_byte = (uint64_t)state->tx_rate_kib_cycle * 1024;
	}

	pkt_len = pkt_ctx_to_pkt(ctx)->pkt_len;
	if (pkt_len > state->budget_byte)
		return GK_BPF_PKT_RET_DECLINE;
	state->budget_byte -= pkt_len;

	if (ctx->now >= state->send_next_renewal_at) {
		state->send_next_renewal_at = ctx->now +
			state->renewal_step_cycle;
		priority = PRIORITY_RENEW_CAP;
	}

	if (gk_bpf_prep_for_tx(ctx, priority, false) < 0)
		return GK_BPF_PKT_RET_ERROR;

	return GK_BPF_PKT_RET_FORWARD;
}
