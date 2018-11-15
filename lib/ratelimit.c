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

#include <math.h>

#include <rte_cycles.h>
#include <rte_common.h>

#include "gatekeeper_main.h"
#include "gatekeeper_ratelimit.h"

void
tb_ratelimit_state_init(struct token_bucket_ratelimit_state *tbrs,
	uint32_t rate, uint32_t burst)
{
	tbrs->rate = rate;
	tbrs->burst = burst;
	tbrs->credit = burst;
	tbrs->stamp = 0;
}

bool
tb_ratelimit_allow(struct token_bucket_ratelimit_state *tbrs)
{
	uint32_t credit, incr = 0;
	uint64_t now = rte_rdtsc(), delta;
	bool rc = false;

	delta = RTE_MIN(now - tbrs->stamp, cycles_per_sec);

	/* Check if token bucket is empty and cannot be refilled. */
	if (!tbrs->credit) {
		if (delta < cycles_per_sec / tbrs->burst)
			return rc;
	}

	if (delta >= cycles_per_sec / tbrs->burst) {
		incr = round((double)(tbrs->rate * delta) / cycles_per_sec);
		if (incr)
			tbrs->stamp = now;
	}
	credit = RTE_MIN(tbrs->credit + incr, tbrs->burst);
	if (credit) {
		credit--;
		rc = true;
	}
	tbrs->credit = credit;

	return rc;
}
