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

#ifndef _GATEKEEPER_LOG_RATELIMIT_H_
#define _GATEKEEPER_LOG_RATELIMIT_H_

#include <stdbool.h>
#include <stdint.h>

/*
 * At startup, log ratelimiting is disabled so that all
 * startup logs are captured. Before the blocks start,
 * the launch routine calls this function to enable log
 * ratelimiting during operation.
 */
void log_ratelimit_enable(void);

/*
 * Check whether a log entry will be permitted, according to the level
 * of the log entry and the configured level of the system's log.
 * Note that even when this test passes, log entries may not occur
 * due to the rate limiting system.
 */
static inline bool
check_log_allowed(uint32_t level, uint32_t logtype)
{
	int sys_level = rte_log_get_level(logtype);
	if (unlikely(sys_level < 0))
		false;

	return level <= (typeof(level))sys_level;
}

 /*
  * @lcore_id: initialize the log_ratelimit_state data for @lcore_id.
  *
  * This will allow to enforce a rate limit on log entries:
  * no more than @log_ratelimit_state.burst callbacks in
  * every @log_ratelimit_state.interval milliseconds.
  *
  * Note that, to avoid performance degradation caused by locks, the
  * implementation assumes that each lcore will maintain a separate
  * struct log_ratelimit_state to rate limit the log entries.
  */
void log_ratelimit_state_init(unsigned int lcore_id, uint32_t interval,
	uint32_t burst, uint32_t log_level, const char *block_name);

/**
 * Generates and ratelimits a log message.
 *
 * The message will be sent in the stream defined by the previous call
 * to rte_openlog_stream() if it is not ratelimited.
 *
 * The level argument determines if the log should be displayed or
 * not, depending on the global rte_logs variable.
 *
 * @param level
 *   Log level. A value between RTE_LOG_EMERG (1) and RTE_LOG_DEBUG (8).
 * @param logtype
 *   The log type, for example, RTE_LOGTYPE_EAL.
 * @param format
 *   The format string, as in printf(3), followed by the variable arguments
 *   required by the format.
 * @return
 *   - 0: Success.
 *   - Negative on error.
 */
int rte_log_ratelimit(uint32_t level, uint32_t logtype, const char *format, ...)
#ifdef __GNUC__
#if (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 2))
	__attribute__((cold))
#endif
#endif
	__attribute__((format(printf, 3, 4)));

/* Functions to set the log level for each functional block as well as lcore. */
void set_log_level_per_block(const char *block_name, uint32_t log_level);
int set_log_level_per_lcore(unsigned int lcore_id, uint32_t log_level);

/* Get the block name for the corresponding lcore. */
const char *get_block_name(unsigned int lcore_id);

#endif /* _GATEKEEPER_LOG_RATELIMIT_H_ */
