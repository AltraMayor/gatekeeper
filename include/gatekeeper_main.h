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

#endif /* _GATEKEEPER_MAIN_H_ */
