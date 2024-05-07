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

#include <stdbool.h>
#include <string.h>
#include <math.h>

#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_memory.h>

#include "gatekeeper_main.h"
#include "gatekeeper_log_ratelimit.h"

RTE_DEFINE_PER_LCORE(struct log_thread_time, _log_thread_time);
struct log_ratelimit_state log_ratelimit_states[RTE_MAX_LCORE];
bool log_ratelimit_enabled;

void
log_ratelimit_enable(void)
{
	log_ratelimit_enabled = true;
}

bool
check_log_allowed(uint32_t level)
{
	struct log_ratelimit_state *lrs = &log_ratelimit_states[rte_lcore_id()];
	return level <= (uint32_t)rte_atomic32_read(&lrs->log_level);
}

#define NO_TIME_STR "NO TIME"

static void
update_str_date_time(uint64_t now)
{
	struct log_thread_time *ttime = &RTE_PER_LCORE(_log_thread_time);
	struct timespec tp;
	struct tm *p_tm, time_info;
	uint64_t diff_ns;
	int ret;

	RTE_BUILD_BUG_ON(sizeof(NO_TIME_STR) > sizeof(ttime->str_date_time));

	if (likely(now < ttime->update_time_at)) {
		/* Fast path, that is, high log rate. */
		return;
	}

	ret = clock_gettime(CLOCK_REALTIME, &tp);
	if (unlikely(ret < 0)) {
		/* Things are bad; fail safe. */
		goto no_tp;
	}

	/* @tp is available from now on. */

	p_tm = localtime_r(&tp.tv_sec, &time_info);
	if (unlikely(p_tm != &time_info))
		goto no_time;

	ret = strftime(ttime->str_date_time, sizeof(ttime->str_date_time),
		"%Y-%m-%d %H:%M:%S", &time_info);
	if (unlikely(ret == 0))
		goto no_time;

	goto next_update;

no_tp:
	tp.tv_nsec = 0;
no_time:
	strcpy(ttime->str_date_time, NO_TIME_STR);
next_update:
	diff_ns = likely(tp.tv_nsec >= 0 && tp.tv_nsec < ONE_SEC_IN_NANO_SEC)
		? (ONE_SEC_IN_NANO_SEC - tp.tv_nsec)
		: ONE_SEC_IN_NANO_SEC; /* C library bug! */
	ttime->update_time_at =
		now + (typeof(now))round(diff_ns * cycles_per_ns);
}

static void
log_ratelimit_reset(struct log_ratelimit_state *lrs, uint64_t now)
{
	lrs->printed = 0;
	if (lrs->suppressed > 0) {
		update_str_date_time(now);
		rte_log(RTE_LOG_NOTICE, BLOCK_LOGTYPE,
			G_LOG_PREFIX "%u log entries were suppressed during the last ratelimit interval\n",
			lrs->block_name, rte_lcore_id(),
			RTE_PER_LCORE(_log_thread_time).str_date_time,
			"NOTICE", lrs->suppressed);
	}
	lrs->suppressed = 0;
	lrs->end = now + lrs->interval_cycles;
}

void
log_ratelimit_state_init(unsigned int lcore_id, uint32_t interval,
	uint32_t burst, uint32_t log_level, const char *block_name)
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
log_ratelimit_allow(struct log_ratelimit_state *lrs, uint64_t now)
{
	/* unlikely() reason: all logs are rate-limited in production. */
	if (unlikely(lrs->interval_cycles == 0))
		return true;

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
gatekeeper_log_ratelimit(uint32_t level, uint32_t logtype,
	const char *format, ...)
{
	uint64_t now = rte_rdtsc(); /* Freeze current time. */
	struct log_ratelimit_state *lrs = &log_ratelimit_states[rte_lcore_id()];
	va_list ap;
	int ret;

	/*
	 * unlikely() reason: @log_ratelimit_enabled is only false during
	 * startup.
	 */
	if (unlikely(!log_ratelimit_enabled))
		goto log;

	if (level <= (uint32_t)rte_atomic32_read(&lrs->log_level) &&
			log_ratelimit_allow(lrs, now))
		goto log;

	return 0;

log:
	update_str_date_time(now);
	va_start(ap, format);
	ret = rte_vlog(level, logtype, format, ap);
	va_end(ap);
	return ret;
}

int
gatekeeper_log_main(uint32_t level, uint32_t logtype, const char *format, ...)
{
	va_list ap;
	int ret;

	update_str_date_time(rte_rdtsc());
	va_start(ap, format);
	ret = rte_vlog(level, logtype, format, ap);
	va_end(ap);
	return ret;
}

int
set_log_level_per_block(const char *block_name, uint32_t log_level)
{
	int n = 0;
	for (int i = 0; i < RTE_MAX_LCORE; i++) {
		if(strcmp(log_ratelimit_states[i].block_name,
				block_name) == 0) {
			rte_atomic32_set(&log_ratelimit_states[i].log_level,
				log_level);
			n++;
		}
	}
	return n;
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
