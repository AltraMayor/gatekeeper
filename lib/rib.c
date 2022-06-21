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

#include "gatekeeper_rib.h"

int
rib_create(struct rib_head *rib, const char *name, int socket_id,
	uint8_t max_length, uint32_t max_rules)
{
	/* TODO */
	RTE_SET_USED(rib);
	RTE_SET_USED(name);
	RTE_SET_USED(socket_id);
	RTE_SET_USED(max_length);
	RTE_SET_USED(max_rules);
	return -1;
}

void
rib_free(struct rib_head *rib)
{
	/* TODO */
	RTE_SET_USED(rib);
}

int
rib_lookup(const struct rib_head *rib, const uint8_t *address,
	uint32_t *pnext_hop)
{
	/* TODO */
	RTE_SET_USED(rib);
	RTE_SET_USED(address);
	RTE_SET_USED(pnext_hop);
	return -1;
}

int
rib_is_rule_present(const struct rib_head *rib, const uint8_t *address,
	uint8_t depth, uint32_t *pnext_hop)
{
	/* TODO */
	RTE_SET_USED(rib);
	RTE_SET_USED(address);
	RTE_SET_USED(depth);
	RTE_SET_USED(pnext_hop);
	return -1;
}

int
rib_add(struct rib_head *rib, const uint8_t *address, uint8_t depth,
	uint32_t next_hop)
{
	/* TODO */
	RTE_SET_USED(rib);
	RTE_SET_USED(address);
	RTE_SET_USED(depth);
	RTE_SET_USED(next_hop);
	return -1;
}

int
rib_delete(struct rib_head *rib, const uint8_t *address, uint8_t depth)
{
	/* TODO */
	RTE_SET_USED(rib);
	RTE_SET_USED(address);
	RTE_SET_USED(depth);
	return -1;
}

int
rib_longer_iterator_state_init(struct rib_longer_iterator_state *state,
	const struct rib_head *rib, const uint8_t *address, uint8_t depth)
{
	/* TODO */
	RTE_SET_USED(state);
	RTE_SET_USED(rib);
	RTE_SET_USED(address);
	RTE_SET_USED(depth);
	return -1;
}

int
rib_longer_iterator_next(struct rib_longer_iterator_state *state,
	struct rib_iterator_rule *rule)
{
	/* TODO */
	RTE_SET_USED(state);
	RTE_SET_USED(rule);
	return -1;
}

int
rib_shorter_iterator_state_init(struct rib_shorter_iterator_state *state,
	const struct rib_head *rib, const uint8_t *address, uint8_t depth)
{
	/* TODO */
	RTE_SET_USED(state);
	RTE_SET_USED(rib);
	RTE_SET_USED(address);
	RTE_SET_USED(depth);
	return -1;
}

int
rib_shorter_iterator_next(struct rib_shorter_iterator_state *state,
	struct rib_iterator_rule *rule)
{
	/* TODO */
	RTE_SET_USED(state);
	RTE_SET_USED(rule);
	return -1;
}
