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
#include <string.h>

#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_memory.h>

#include "gatekeeper_main.h"
#include "gatekeeper_log_ratelimit.h"

struct log_ratelimit_state {
	uint64_t       interval_cycles;
	uint32_t       burst;
	uint32_t       printed;
	uint32_t       suppressed;
	uint64_t       end;
	rte_atomic32_t log_level;
	char           block_name[16];
} __rte_cache_aligned;

static struct log_ratelimit_state log_ratelimit_states[RTE_MAX_LCORE];

static bool enabled;

void
log_ratelimit_enable(void)
{
	enabled = true;
}

static inline void
log_ratelimit_reset(struct log_ratelimit_state *lrs, uint64_t now)
{
	lrs->printed = 0;
	if (lrs->suppressed > 0) {
		rte_log(RTE_LOG_NOTICE, gatekeeper_logtype,
			"GATEKEEPER %s: %u log entries were suppressed at lcore %u during the last ratelimit interval\n",
			lrs->block_name, lrs->suppressed, rte_lcore_id());
	}
	lrs->suppressed = 0;
	lrs->end = now + lrs->interval_cycles;
}

void
log_ratelimit_state_init(unsigned int lcore_id, uint32_t interval, uint32_t burst,
	uint32_t log_level, const char *block_name)
{
	struct log_ratelimit_state *lrs;

	RTE_VERIFY(lcore_id < RTE_MAX_LCORE);

	lrs = &log_ratelimit_states[lcore_id];

	RTE_VERIFY(strlen(block_name) < sizeof(lrs->block_name));

	lrs->interval_cycles = interval * cycles_per_ms;
	lrs->burst = burst;
	lrs->suppressed = 0;
	rte_atomic32_set(&lrs->log_level, log_level);
	strcpy(lrs->block_name, block_name);
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

	/* unlikely() reason: @enabled is only false during startup. */
	if (unlikely(!enabled))
		return true;

	/* unlikely() reason: all logs are rate-limited in production. */
	if (unlikely(lrs->interval_cycles == 0))
		return true;

	now = rte_rdtsc();

	/*
	 * unlikely() reason: there is only one
	 * reset every @lrs->interval_cycles.
	 */
	if (unlikely(lrs->end < now))
		log_ratelimit_reset(lrs, now);

	if (lrs->burst > lrs->printed) {
		lrs->printed++;
		return true;
	}

	lrs->suppressed++;

	return false;
}

int
rte_log_ratelimit(uint32_t level, uint32_t logtype, const char *format, ...)
{
	struct log_ratelimit_state *lrs = &log_ratelimit_states[rte_lcore_id()];
	if (level <= (uint32_t)rte_atomic32_read(&lrs->log_level) &&
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

void
set_log_level_per_block(const char *block_name, uint32_t log_level)
{
	for (int i = 0; i < RTE_MAX_LCORE; i++) {
		if(strcmp(log_ratelimit_states[i].block_name,
				block_name) == 0) {
			rte_atomic32_set(&log_ratelimit_states[i].log_level,
				log_level);
		}
	}
}

int
set_log_level_per_lcore(unsigned int lcore_id, uint32_t log_level)
{
	if (lcore_id >= RTE_MAX_LCORE) {
		return -1;
	}
	rte_atomic32_set(&log_ratelimit_states[lcore_id].log_level, log_level);
	return 0;
}

const char *
get_block_name(unsigned int lcore_id)
{
	if (lcore_id >= RTE_MAX_LCORE) {
		return "invalid lcore";
	}
	return log_ratelimit_states[lcore_id].block_name;
}
