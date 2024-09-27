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

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>

#include <rte_common.h>
#include <rte_mbuf_core.h>
#include <rte_branch_prediction.h>

#include "gatekeeper_flow_bpf.h"
#include "libicmp.h"

#define TCPSRV_MAX_NUM_PORTS (12)

struct tcpsrv_ports {
	uint16_t p[TCPSRV_MAX_NUM_PORTS];
};

struct tcpsrv_params {
	/*
	 * Primary rate limit: kibibyte/second.
	 * This limit can never be exceeded.
	 */
	uint32_t tx1_rate_kib_sec;
	/*
	 * The first value of send_next_renewal_at at
	 * flow entry comes from next_renewal_ms.
	 */
	uint32_t next_renewal_ms;
	/*
	 * How many milliseconds (unit) GK must wait
	 * before sending the next capability renewal request.
	 */
	uint32_t renewal_step_ms:24;
	/* Number of listening ports. */
	uint8_t listening_port_count:4;
	/* Number of remote ports. */
	uint8_t remote_port_count:4;
	/*
	 * The listening ports start at index zero and
	 * go toward index (@listening_port_count - 1).
	 * Whereas the remote ports start at index (TCPSRV_MAX_NUM_PORTS - 1)
	 * and go toward index (TCPSRV_MAX_NUM_PORTS - @remote_port_count).
	 * Each set of ports, namely listening and remote ports, must be
	 * 1. sorted in ascending order according to
	 *    how they are laid on the array;
	 * 2. unique.
	 */
	struct tcpsrv_ports ports;
} __attribute__ ((packed));

struct tcpsrv_state {
	/* When @budget_byte is reset. */
	uint64_t budget_renew_at;
	/*
	 * When @budget1_byte is reset,
	 * add @tx1_rate_kib_sec * 1024 bytes to it.
	 */
	uint32_t tx1_rate_kib_sec;
	/*
	 * How many milliseconds (unit) GK must wait
	 * before sending the next capability renewal request.
	 */
	uint32_t renewal_step_ms:24;
	/* Number of listening ports. */
	uint8_t listening_port_count:4;
	/* Number of remote ports. */
	uint8_t remote_port_count:4;
	/* How many bytes @src can still send in current cycle. */
	int64_t budget1_byte;
	/*
	 * How many bytes @src can still send in current cycle in
	 * the secondary channel.
	 */
	int64_t budget2_byte;
	/*
	 * When GK should send the next renewal to
	 * the corresponding grantor.
	 */
	uint64_t send_next_renewal_at;
	/*
	 * The listening ports start at index zero and
	 * go toward index (@listening_port_count - 1).
	 * Whereas the remote ports start at index (TCPSRV_MAX_NUM_PORTS - 1)
	 * and go toward index (TCPSRV_MAX_NUM_PORTS - @remote_port_count).
	 * Each set of ports, namely listening and remote ports, must be
	 * 1. sorted in ascending order according to
	 *    how they are laid on the array;
	 * 2. unique.
	 */
	struct tcpsrv_ports ports;
};

static __rte_always_inline int64_t
reset_budget1(const struct tcpsrv_state *state)
{
	return (int64_t)state->tx1_rate_kib_sec * 1024; /* 1024 B/KiB */
}

static __rte_always_inline void
reset_budget2(struct tcpsrv_state *state)
{
	state->budget2_byte = reset_budget1(state) * 5 / 100; /* 5% */
}


SEC("init") uint64_t
tcpsrv_init(struct gk_bpf_init_ctx *ctx)
{
	struct gk_bpf_cookie *cookie = init_ctx_to_cookie(ctx);
	struct tcpsrv_params params = *(struct tcpsrv_params *)cookie;
	struct tcpsrv_state *state = (struct tcpsrv_state *)cookie;

	RTE_BUILD_BUG_ON(sizeof(params) > sizeof(*cookie));
	RTE_BUILD_BUG_ON(sizeof(*state) > sizeof(*cookie));

	/* Are the number of ports correct? */
	if (unlikely((int)params.listening_port_count +
			params.remote_port_count > TCPSRV_MAX_NUM_PORTS))
		return GK_BPF_INIT_RET_ERROR;

	state->budget_renew_at = ctx->now + cycles_per_sec;
	state->tx1_rate_kib_sec = params.tx1_rate_kib_sec;
	state->renewal_step_ms = params.renewal_step_ms;
	state->listening_port_count = params.listening_port_count;
	state->remote_port_count = params.remote_port_count;
	state->budget1_byte = reset_budget1(state);
	reset_budget2(state);
	state->send_next_renewal_at = ctx->now +
		params.next_renewal_ms * cycles_per_ms;
	state->ports = params.ports;
	return GK_BPF_INIT_RET_OK;
}

static __rte_always_inline uint64_t
tcpsrv_pkt_begin(const struct gk_bpf_pkt_ctx *ctx,
	struct tcpsrv_state *state, uint32_t pkt_len)
{
	if (unlikely(ctx->now >= state->budget_renew_at)) {
		int64_t max_budget1 = reset_budget1(state);
		int64_t cycles = ctx->now - state->budget_renew_at;
		int64_t epochs = cycles / cycles_per_sec;

		state->budget_renew_at = ctx->now + cycles_per_sec -
			(cycles % cycles_per_sec);
		state->budget1_byte += max_budget1 * (epochs + 1);
		if (state->budget1_byte > max_budget1)
			state->budget1_byte = max_budget1;
		reset_budget2(state);
	}

	/* Primary budget. */
	state->budget1_byte -= pkt_len;
	if (state->budget1_byte < 0)
		return GK_BPF_PKT_RET_DECLINE;

	return GK_BPF_PKT_RET_FORWARD;
}

static __rte_always_inline uint64_t
tcpsrv_pkt_test_2nd_limit(struct tcpsrv_state *state, uint32_t pkt_len)
{
	state->budget2_byte -= pkt_len;
	if (state->budget2_byte < 0)
		return GK_BPF_PKT_RET_DECLINE;
	return GK_BPF_PKT_RET_FORWARD;
}

static __rte_always_inline uint64_t
tcpsrv_pkt_end(struct gk_bpf_pkt_ctx *ctx, struct tcpsrv_state *state)
{
	uint8_t priority = PRIORITY_GRANTED;

	if (unlikely(ctx->now >= state->send_next_renewal_at)) {
		state->send_next_renewal_at = ctx->now +
			state->renewal_step_ms * cycles_per_ms;
		priority = PRIORITY_RENEW_CAP;
	}

	if (unlikely(gk_bpf_prep_for_tx(ctx, priority, true) < 0))
		return GK_BPF_PKT_RET_ERROR;

	return GK_BPF_PKT_RET_FORWARD;
}

#define TEST_COUNT(count)				\
	case count:					\
		if (*ports >= port)			\
			break
#define FORWARD ports++

static __rte_always_inline bool
is_port_listed_forward(const uint16_t *ports, uint8_t count, uint16_t port)
{
	RTE_BUILD_BUG_ON(TCPSRV_MAX_NUM_PORTS != 12);

	switch (count) {
	TEST_COUNT(12); FORWARD;
	TEST_COUNT(11); FORWARD;
	TEST_COUNT(10); FORWARD;
	TEST_COUNT(9);  FORWARD;
	TEST_COUNT(8);  FORWARD;
	TEST_COUNT(7);  FORWARD;
	TEST_COUNT(6);  FORWARD;
	TEST_COUNT(5);  FORWARD;
	TEST_COUNT(4);  FORWARD;
	TEST_COUNT(3);  FORWARD;
	TEST_COUNT(2);  FORWARD;
	TEST_COUNT(1);
	default:
		return false;
	}

	return *ports == port;
}

static __rte_always_inline bool
is_listening_port(struct tcpsrv_state *state, uint16_t port_be)
{
	return is_port_listed_forward(&state->ports.p[0],
		state->listening_port_count, ntohs(port_be));
}

#define BACK ports--

static __rte_always_inline bool
is_port_listed_back(const uint16_t *ports, uint8_t count, uint16_t port)
{
	RTE_BUILD_BUG_ON(TCPSRV_MAX_NUM_PORTS != 12);

	switch (count) {
	TEST_COUNT(12); BACK;
	TEST_COUNT(11); BACK;
	TEST_COUNT(10); BACK;
	TEST_COUNT(9);  BACK;
	TEST_COUNT(8);  BACK;
	TEST_COUNT(7);  BACK;
	TEST_COUNT(6);  BACK;
	TEST_COUNT(5);  BACK;
	TEST_COUNT(4);  BACK;
	TEST_COUNT(3);  BACK;
	TEST_COUNT(2);  BACK;
	TEST_COUNT(1);
	default:
		return false;
	}

	return *ports == port;
}

static __rte_always_inline bool
is_remote_port(struct tcpsrv_state *state, uint16_t port_be)
{
	return is_port_listed_back(&state->ports.p[TCPSRV_MAX_NUM_PORTS - 1],
		state->remote_port_count, ntohs(port_be));
}

SEC("pkt") uint64_t
tcpsrv_pkt(struct gk_bpf_pkt_ctx *ctx)
{
	struct tcpsrv_state *state =
		(struct tcpsrv_state *)pkt_ctx_to_cookie(ctx);
	struct rte_mbuf *pkt = pkt_ctx_to_pkt(ctx);
	uint32_t pkt_len = pkt->pkt_len;
	struct tcphdr *tcp_hdr;
	uint64_t ret = tcpsrv_pkt_begin(ctx, state, pkt_len);

	if (ret != GK_BPF_PKT_RET_FORWARD) {
		/* Primary budget exceeded. */
		return ret;
	}

	/* Allowed L4 protocols. */
	switch (ctx->l4_proto) {
	case IPPROTO_ICMP:
		ret = check_icmp(ctx, pkt);
		if (ret != GK_BPF_PKT_RET_FORWARD)
			return ret;
		goto secondary_budget;

	case IPPROTO_ICMPV6:
		ret = check_icmp6(ctx, pkt);
		if (ret != GK_BPF_PKT_RET_FORWARD)
			return ret;
		goto secondary_budget;

	case IPPROTO_TCP:
		break;

	default:
		return GK_BPF_PKT_RET_DECLINE;
	}

	/*
	 * Only TCP packets from here on.
	 */

	if (ctx->fragmented)
		goto secondary_budget;
	if (unlikely(pkt->l4_len < sizeof(*tcp_hdr))) {
		/* Malformed TCP header. */
		return GK_BPF_PKT_RET_DECLINE;
	}
	tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct tcphdr *,
		pkt->l2_len + pkt->l3_len);

	if (is_listening_port(state, tcp_hdr->th_dport)) {
		if (tcp_hdr->syn) {
			if (tcp_hdr->ack) {
				/* Amplification attack. */
				return GK_BPF_PKT_RET_DECLINE;
			}
			/* Contain SYN floods. */
			goto secondary_budget;
		}
	} else {
		/* Accept connections originated from the destination. */

		if (tcp_hdr->syn && !tcp_hdr->ack) {
			/* All listening ports were already tested. */
			return GK_BPF_PKT_RET_DECLINE;
		}

		/* Authorized external services. */
		if (!is_remote_port(state, tcp_hdr->th_sport))
			return GK_BPF_PKT_RET_DECLINE;
	}

	goto forward;

secondary_budget:
	ret = tcpsrv_pkt_test_2nd_limit(state, pkt_len);
	if (ret != GK_BPF_PKT_RET_FORWARD)
		return ret;
forward:
	return tcpsrv_pkt_end(ctx, state);
}
