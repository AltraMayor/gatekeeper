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

#ifndef _GATEKEEPER_RATELIMIT_H_
#define _GATEKEEPER_RATELIMIT_H_

#include <stdint.h>
#include <stdbool.h>

/*
 * The code of this file is mostly a copy of the Linux kernel.
 */

struct token_bucket_ratelimit_state {
	uint32_t rate;
	uint32_t burst;
	uint32_t credit;
	uint64_t stamp;
};

void tb_ratelimit_state_init(struct token_bucket_ratelimit_state *tbrs,
	uint32_t rate, uint32_t burst);
uint32_t tb_ratelimit_allow_n(uint32_t n,
	struct token_bucket_ratelimit_state *tbrs);

static inline bool
tb_ratelimit_allow(struct token_bucket_ratelimit_state *tbrs)
{
	return tb_ratelimit_allow_n(1, tbrs);
}

#endif /* _GATEKEEPER_RATELIMIT_H_ */
