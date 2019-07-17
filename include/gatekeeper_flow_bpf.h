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
 * This files contains all definitions that a BPF program needs to
 * implement a flow handler associated a flow entry.
 */

#ifndef _GATEKEEPER_FLOW_BPF_H_
#define _GATEKEEPER_FLOW_BPF_H_

#include <stdint.h>

/*
 * Helper macro to place BPF programs, maps, and licenses in
 * different sections of an ELF BPF file.
 */
#define SEC(NAME) __attribute__((section(NAME), used))

/*
 * Priority used for DSCP field of encapsulated packets:
 *  0 for legacy packets; 1 for granted packets;
 *  2 for capability renew; 3-63 for request packets.
 */
#define PRIORITY_GRANTED	(1)
#define PRIORITY_RENEW_CAP	(2)
#define PRIORITY_REQ_MIN	(3)
#define PRIORITY_MAX		(63)

/* Memory reserved for a GK BPF program in between runs. */
struct gk_bpf_cookie {
	uint64_t mem[8];
};

/* Possible returns of the function init of a GK BPF program. */
enum gk_bpf_init_return {
	/* The cookie was successfully initialized. */
	GK_BPF_INIT_RET_OK,

	/*
	 * The initialization of a given cookie failed.
	 *
	 * This is not a regular return since failing to initialize a cookie
	 * implies in not fulfilling a policy decision. Thus, this return
	 * should only be returned under extreme conditions.
	 */
	GK_BPF_INIT_RET_ERROR
};

/* The context of a GK BPF program for function init. */
struct gk_bpf_init_ctx {
	uint64_t now;
};

/* Possible returns of the function pkt of a GK BPF program. */
enum gk_bpf_pkt_return {
	/*
	 * The packet is always forwarded toward the grantor server.
	 * The packet is accounted as at state GK_GRANTED.
	 */
	GK_BPF_PKT_RET_FORWARD,

	/* The packet is dropped, but account as at state GK_DECLINED. */
	GK_BPF_PKT_RET_DECLINE,

	/* Some error happened during processing. The packet will be dropped. */
	GK_BPF_PKT_RET_ERROR
};

/*
 * The context of a GK BPF program for function pkt.
 *
 * The GK block guarantees that @now < @expire_at, that is,
 * the BPF state has not expired.
 */
struct gk_bpf_pkt_ctx {
	uint64_t now;
	uint64_t expire_at;
};

/*
 * The define GK_BPF_INTERNAL, used below, should only be defined
 * in bk/bpf.c.
 */
#ifndef GK_BPF_INTERNAL
#define GK_BPF_INTERNAL extern
#endif

/* Symbols available to the BPF functions init() and pkt(). */
GK_BPF_INTERNAL uint64_t cycles_per_sec;
GK_BPF_INTERNAL uint64_t cycles_per_ms;

/* Symbols available to the BPF function init(). */
GK_BPF_INTERNAL struct gk_bpf_cookie *init_ctx_to_cookie(
	struct gk_bpf_init_ctx *ctx);

/* Symbols available to the BPF function pkt(). */
GK_BPF_INTERNAL struct gk_bpf_cookie *pkt_ctx_to_cookie(
	struct gk_bpf_pkt_ctx *ctx);
GK_BPF_INTERNAL struct rte_mbuf *pkt_ctx_to_pkt(struct gk_bpf_pkt_ctx *ctx);
GK_BPF_INTERNAL int gk_bpf_encapsulate(struct gk_bpf_pkt_ctx *ctx,
	int priority, int direct_if_possible);

#endif /* _GATEKEEPER_FLOW_BPF_H_ */
