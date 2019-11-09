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

#ifndef _GATEKEEPER_MAIN_H_
#define _GATEKEEPER_MAIN_H_

#include <stdint.h>
#include <stdbool.h>

#include <rte_mbuf.h>
#include <rte_prefetch.h>

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC       rte_jhash
#endif

#include "gatekeeper_log_ratelimit.h"

/*
 * Custom log type for Gatekeeper-related log entries
 * that are not relevant to a specific block.
 */
extern int gatekeeper_logtype;

#define G_LOG(level, ...)		        \
	rte_log_ratelimit(RTE_LOG_ ## level,	\
	gatekeeper_logtype, "GATEKEEPER: " __VA_ARGS__)

extern volatile int exiting;

extern uint64_t cycles_per_sec;
extern uint64_t cycles_per_ms;
extern uint64_t picosec_per_cycle;

extern FILE *log_file;

char *rte_strdup(const char *type, const char *s);
int gatekeeper_log_init(void);

/* XXX #52 This should be part of DPDK. */
/**
 * Prefetch the first part of the mbuf
 *
 * The first 64 bytes of the mbuf corresponds to fields that are used early
 * in the receive path. If the cache line of the architecture is higher than
 * 64B, the second part will also be prefetched.
 *
 * @param m
 *   The pointer to the mbuf.
 */
static inline void
rte_mbuf_prefetch_part1_non_temporal(struct rte_mbuf *m)
{
	rte_prefetch_non_temporal(&m->cacheline0);
}

/* XXX #52 This should be part of DPDK. */
/**
 * Prefetch the second part of the mbuf
 *
 * The next 64 bytes of the mbuf corresponds to fields that are used in the
 * transmit path. If the cache line of the architecture is higher than 64B,
 * this function does nothing as it is expected that the full mbuf is
 * already in cache.
 *
 * @param m
 *   The pointer to the mbuf.
 */
static inline bool
rte_mbuf_prefetch_part2_non_temporal(struct rte_mbuf *m)
{
#if RTE_CACHE_LINE_SIZE == 64
	/* TODO Do we need this prefetch?
	rte_prefetch_non_temporal(&m->cacheline1);
	return true;
	*/
	RTE_SET_USED(m);
	return false;
#else
	RTE_SET_USED(m);
	return false;
#endif
}

#endif /* _GATEKEEPER_MAIN_H_ */
