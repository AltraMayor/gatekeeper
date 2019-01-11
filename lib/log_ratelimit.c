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

#include <stdbool.h>

#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_memory.h>

#include "gatekeeper_main.h"
#include "gatekeeper_log_ratelimit.h"

struct log_ratelimit_state {
	uint64_t interval_cycles;
	uint32_t burst;
	uint32_t printed;
	uint64_t end;
} __rte_cache_aligned;

static struct log_ratelimit_state log_ratelimit_states[RTE_MAX_LCORE];

static inline void
log_ratelimit_reset(struct log_ratelimit_state *lrs, uint64_t now)
{
	lrs->printed = 0;
	lrs->end = now + lrs->interval_cycles;
}

void
log_ratelimit_state_init(unsigned lcore_id, uint32_t interval, uint32_t burst)
{
	struct log_ratelimit_state *lrs;

	RTE_VERIFY(lcore_id < RTE_MAX_LCORE);

	lrs = &log_ratelimit_states[lcore_id];
	lrs->interval_cycles = interval * cycles_per_ms;
	lrs->burst = burst;
	log_ratelimit_reset(lrs, rte_rdtsc());
}

/*
 * Rate limiting log entries.
 *
 * Returns:
 * - true means go ahead and do it.
 * - false means callbacks will be suppressed.
 */
static bool
log_ratelimit_allow(struct log_ratelimit_state *lrs)
{
	uint64_t now;

	if (lrs->interval_cycles == 0)
		return true;

	now = rte_rdtsc();

	if (lrs->end < now)
		log_ratelimit_reset(lrs, now);

	if (lrs->burst > lrs->printed) {
		lrs->printed++;
		return true;
	}

	return false;
}

int
rte_log_ratelimit(uint32_t level, uint32_t logtype, const char *format, ...)
{
	struct log_ratelimit_state *lrs;
	int ratelimit_level = rte_log_get_level(logtype);
	if (unlikely(ratelimit_level < 0))
		return -1;

	lrs = &log_ratelimit_states[rte_lcore_id()];
	if (level <= (typeof(level))ratelimit_level &&
			log_ratelimit_allow(lrs)) {
		int ret;
		va_list ap;

		va_start(ap, format);
		ret = rte_vlog(level, logtype, format, ap);
		va_end(ap);

		return ret;
	}

	return 0;
}
