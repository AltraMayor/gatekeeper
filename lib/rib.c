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

#include <rte_byteorder.h>
#include <rte_errno.h>

#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
#include <rte_memcpy.h>
#endif

#include "gatekeeper_main.h"
#include "gatekeeper_rib.h"

static int
__read_addr(uint8_t length, rib_address_t *cpu_addr, const uint8_t *address)
{
	if (unlikely(address == NULL)) {
		*cpu_addr = 0;
		return 0;
	}

	switch (length) {
        case 32:
		*cpu_addr = rte_be_to_cpu_32(*((uint32_t *)address));
		break;

	case 128: {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
		uint64_t *dst = (uint64_t *)cpu_addr;
		uint64_t *src = (uint64_t *)address;
		dst[0] = rte_be_to_cpu_64(src[1]);
		dst[1] = rte_be_to_cpu_64(src[0]);
#else /* RTE_BIG_ENDIAN */
		RTE_BUILD_BUG_ON(sizeof(*cpu_addr) != sizeof(uint128_t));
		rte_mov128((uint8_t *)cpu_addr, address);
#endif
		break;
	}

	default:
		G_LOG(ERR, "%s(): length=%u is not implemented\n",
			__func__, length);
		return -EINVAL;
	}
	return 0;
}

static inline int
read_addr(const struct rib_head *rib, rib_address_t *cpu_addr,
	const uint8_t *address)
{
	return __read_addr(rib->max_length, cpu_addr, address);
}

static int
__write_addr(uint8_t length, uint8_t *address, rib_address_t cpu_addr)
{
	switch (length) {
	case 32:
		*((uint32_t *)address) = rte_cpu_to_be_32(cpu_addr);
		break;

	case 128: {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
		uint64_t *dst = (uint64_t *)address;
		uint64_t *src = (uint64_t *)&cpu_addr;
		dst[0] = rte_cpu_to_be_64(src[1]);
		dst[1] = rte_cpu_to_be_64(src[0]);
#else /* RTE_BIG_ENDIAN */
		RTE_BUILD_BUG_ON(sizeof(cpu_addr) != sizeof(uint128_t));
		rte_mov128(address, (uint8_t *)&cpu_addr);
#endif
		break;
	}

	default:
		G_LOG(ERR, "%s(): length=%u is not implemented\n",
			__func__, length);
		return -EINVAL;
	}
	return 0;
}

static inline int
write_addr(const struct rib_head *rib, uint8_t *address, rib_address_t cpu_addr)
{
	return __write_addr(rib->max_length, address, cpu_addr);
}

int
rib_create(struct rib_head *rib, const char *name, int socket_id,
	uint8_t max_length, uint32_t max_rules)
{
	rib_address_t dummy;
	int ret;
	unsigned int n;

	if (unlikely(max_length > RIB_MAX_ADDRESS_LENGTH)) {
		G_LOG(ERR, "%s(): max_length=%u is greater than RIB_MAX_ADDRESS_LENGTH=%i\n",
			__func__, max_length, RIB_MAX_ADDRESS_LENGTH);
		return -EINVAL;
	}

	if (unlikely((max_length & 0x7) > 0)) {
		G_LOG(ERR, "%s(): max_length=%u is not a multiple of 8\n",
			__func__, max_length);
		return -EINVAL;
	}

	ret = __read_addr(max_length, &dummy, (const uint8_t *)&dummy);
	if (unlikely(ret < 0))
		return ret;

	ret = __write_addr(max_length, (uint8_t *)&dummy, 0);
	if (unlikely(ret < 0))
		return ret;

	memset(rib, 0, sizeof(*rib));
	rib->max_length = max_length;

	/*
	 * Number of nodes needed to store a max-length prefix.
	 * Adding (RIB_MAX_PREFIX_BITS - 1) is equivalent to rouding up
	 * the result since it's an integer division.
	 */
	n = (max_length + RIB_MAX_PREFIX_BITS - 1) / RIB_MAX_PREFIX_BITS;
	/*
	 * rib_add() needs at most a new internal node when adding
	 * a prefix to the RIB.
	 */
	n++;
	/*
	 * Loose upper bound on the number of nodes needed to have
	 * @max_rules rules.
	 */
	n *= max_rules;

	rib->mp_nodes = rte_mempool_create(name, n, sizeof(struct rib_node),
		0, 0, NULL, NULL, NULL, NULL, socket_id,
		/* Save memory; struct rib_node is small. */
		MEMPOOL_F_NO_SPREAD | MEMPOOL_F_NO_CACHE_ALIGN |
		/* No synchronization; single writer. */
		MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET |
		/* Nodes are not used for I/O. */
		MEMPOOL_F_NO_IOVA_CONTIG);
	if (unlikely(rib->mp_nodes == NULL)) {
		ret = rte_errno;
		G_LOG(ERR, "%s(): cannot create memory pool (errno=%i): %s\n",
			__func__, ret, rte_strerror(ret));
		return -ret;
	}

	return 0;
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
