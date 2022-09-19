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

#ifndef _GATEKEEPER_GK_RIB_H_
#define _GATEKEEPER_GK_RIB_H_

#include <stdint.h>
#include <setjmp.h>

#include <rte_mempool.h>

typedef unsigned __int128 uint128_t;

/*
 * Internal representation of an address.
 * Unless explicitly noticed, the bits are in host order.
 */
typedef uint128_t rib_address_t;

#define RIB_MAX_ADDRESS_LENGTH ((int)sizeof(rib_address_t) * 8)

typedef uint64_t rib_prefix_bits_t;

#define RIB_MAX_PREFIX_BITS ((int)sizeof(rib_prefix_bits_t) * 8)

struct rib_node {
	/*
	 * Bits of the prefix to be matched.
	 * These bits are kept in host order,
	 * so they can be directly operated on.
	 */
	rib_prefix_bits_t pfx_bits;
	/* The number of bits present in @pfx_bits. */
	uint8_t           matched_bits;
	/* True if there is a value at @next_hop. */
	bool              has_nh;
	/* Next hop if the prefix matches all @matched_bits bits. */
	uint32_t          next_hop;
	/*
	 * The branches after this node.
	 * @branch[false] is the branch that follows this node when the first
	 * not-matched bit is zero, and @branch[true] when the first
	 * not-matched bit is one.
	 * @branch[false] or @branch[true] is NULL when those branches
	 * do not exist.
	 */
	struct rib_node   *branch[2];
};

struct rib_head {
	/* Maximum length of a network address. */
	uint8_t            max_length;

	/*
	 * Version of the RIB.
	 * @version changes every time the RIB is edited.
	 * The main purpose of this field is to support iterators.
	 */
	uint64_t           version;

	/*
	 * Root of the prefix tree.
	 *
	 * When the field @has_nh is true, the RIB has the default prefix
	 * (i.e. the zero-length prefix). When the default prefix is present,
	 * its next hop is at field @next_hop.
	 *
	 * This is the only node in the prefix tree that has field
	 * @matched_bits equal to zero, all other nodes have a value
	 * greater than zero at this field.
	 */
	struct rib_node    root_node;

	/* Memory pool for instances of struct rib_node. */
	struct rte_mempool *mp_nodes;
};

/*
 * Create a new RIB.
 *
 * @name of the internal memory pool used to allocate the nodes of
 * the prefix tree.
 *
 * @socket_id is the NUMA node on which internal memory is allocated.
 * The value can be SOCKET_ID_ANY if there is no NUMA constraint.
 *
 * @max_length is the maximum length of a network address.
 * @max_length must be a multiple of 8 and not greater than
 * RIB_MAX_ADDRESS_LENGTH.
 * Typical values: 32 for IPv4 and 128 for IPv6.
 *
 * @max_rules is the maximum number of rules (i.e. a prefix and a next hop)
 * that this RIB is expected to have. If the RIB has space for more rules,
 * it will take extra rules. Inspite of the name, this parameter is meant
 * to mean the minimum number of rules that the RIB will support.
 * The chosen name is meant to match the name of the field max_rules in
 * struct rte_lpm_config and struct rte_lpm6_config.
 */
int rib_create(struct rib_head *rib, const char *name, int socket_id,
	uint8_t max_length, uint32_t max_rules);

/* Free all resources associated to @rib but the memory pointed by it. */
void rib_free(struct rib_head *rib);

/*
 * Add a rule to the RIB.
 * @address is in network order (big endian).
 * @address == NULL is equivalent to the all-zero address.
 * RETURN
 * 	-EEXIST if prefix already exist in @rib.
 * 	0 if it successfully adds the new rule.
 */
int rib_add(struct rib_head *rib, const uint8_t *address, uint8_t depth,
	uint32_t next_hop);

/*
 * Delete a rule from the RIB.
 * @address is in network order (big endian).
 * @address == NULL is equivalent to the all-zero address.
 * RETURN
 * 	-ENOENT if the prefix does not exist in @rib.
 * 	0 if it successfully deletes the rule.
 */
int rib_delete(struct rib_head *rib, const uint8_t *address, uint8_t depth);

/*
 * Look an address up on the RIB.
 * @address is in network order (big endian).
 * @address == NULL is equivalent to the all-zero address.
 * RETURN
 *	0 on lookup hit.
 *	-ENOENT on lookup miss.
 * 	A negative value on failure.
 *
 */
int rib_lookup(const struct rib_head *rib, const uint8_t *address,
	uint32_t *pnext_hop);

/*
 * Check if a rule is present in the RIB, and provide its next hop if it is.
 * @address is in network order (big endian).
 * @address == NULL is equivalent to the all-zero address.
 * RETURN
 * 	1 if the rule exists.
 * 	0 if it does not.
 * 	A negative value on failure.
 */
int rib_is_rule_present(const struct rib_head *rib, const uint8_t *address,
	uint8_t depth, uint32_t *pnext_hop);

/*
 * Extra information about struct rib_node that can be computed as
 * one navigates a RIB.
 */
struct rib_node_info {
	/* Prefix in host order that has been matched up to the current node. */
	rib_address_t haddr_matched;
	/* Bit mask for field @haddr_matched. */
	rib_address_t haddr_mask;
	/* Number of bits set in field @haddr_mask. */
	int           depth;
	/*
	 * Number of bits missing in field @haddr_mask to reach
	 * the maximum mask.
	 */
	int           missing_bits;
};

struct rib_iterator_rule {
	rib_address_t address_no; /* Address in network order. */
	uint8_t       depth;
	uint32_t      next_hop;
};

static inline uint32_t
ipv4_from_rib_addr(rib_address_t address_no)
{
	uint32_t *p = (typeof(p))&address_no;
	return *p;
}

struct rib_longer_iterator_state {
	/* RIB with which the iterator is associated. */
	const struct rib_head    *rib;

	/*
	 * RIB scope of the iterator.
	 */

	/* Version of the RIB for which field @start_node is valid. */
	uint64_t                 version;
	/* Node where the iterator starts. */
	const struct rib_node    *start_node;
	/* Information associated with field @start_node. */
	struct rib_node_info     start_info;
	/* The minimum depth of prefix in field @next_address; the scope. */
	uint8_t                  min_depth;

	/*
	 * The following fields are used in between calls of
	 * rib_longer_iterator_next().
	 */

	/*
	 * The next prefix to be returned by rib_longer_iterator_next().
	 *
	 * If the prefix does not exist in the RIB,
	 * the prefix immediately greater will be returned.
	 */
	rib_address_t            next_address;
	/* The depth of the prefix in field @next_address. */
	uint8_t                  next_depth;
	/* The iterator has finished. */
	bool                     has_ended;

	/*
	 * The following fields are set and only valid while execution is in
	 * rib_longer_iterator_next().
	 */

	/* When true, keep looking for prefixes greater than @next_address. */
	bool                     ignore_next_address;
	/* A return for rib_longer_iterator_next() has been found. */
	bool                     found_return;
	/*
	 * Pointer to the struct rib_iterator_rule that will receive
	 * the found rule; the output.
	 */
	struct rib_iterator_rule *rule;
	/* Long jump to unwind the recursion. */
	jmp_buf                  jmp_found;
};

/*
 * Initialize @state.
 *
 * The first call of rib_longer_iterator_next() returns a rule whose prefix
 * is at least as deeper as @depth.
 *
 * Passing @address = NULL (or any other value) and @depth = 0 iterates
 * over the whole RIB; including the default rule
 * (i.e. the zero-length prefix).
 *
 * @address is in network order (big endian).
 * @address == NULL is equivalent to the all-zero address.
 *
 * If the RIB changes (i.e. rules are added or deleted)
 * between the call of this function and the call of
 * rib_longer_iterator_next(), or between two consecutive calls of
 * rib_longer_iterator_next(), the iterator will enumerate the changes that
 * are within the scope of the iterator (i.e at least as deeper than
 * the initial prefix) and that are after the next rule.
 */
int rib_longer_iterator_state_init(struct rib_longer_iterator_state *state,
	const struct rib_head *rib, const uint8_t *address, uint8_t depth);

/*
 * When a rule is found, this function updates @rule and returns zero.
 * Otherwise, this function returns -ENOENT.
 */
int rib_longer_iterator_next(struct rib_longer_iterator_state *state,
	struct rib_iterator_rule *rule);

/*
 * Free all resources associated to @state but the memory pointed by it.
 *
 * CAUTION: This function should only be called on initialized states.
 */
static inline void
rib_longer_iterator_end(struct rib_longer_iterator_state *state)
{
	/* At the current version of the code, there is nothing to do here. */
	RTE_SET_USED(state);
}

struct rib_shorter_iterator_state {
	/* RIB with which the iterator is associated. */
	const struct rib_head *rib;
	/* Version of the RIB for which field @cur_node is valid. */
	uint64_t              version;
	/* Current node of the iteration. */
	const struct rib_node *cur_node;
	/* Information associated with field @cur_node. */
	struct rib_node_info  info;
	/* Deepest prefix to consider. */
	rib_address_t         haddr;
	uint8_t               depth;
	/* The iterator has finished. */
	bool                  has_ended;
};

/*
 * Initialize @state.
 *
 * The first call of rib_shorter_iterator_next() returns a rule whose prefix
 * is at most as deep as @depth and includes @address.
 *
 * The prefix @address/@depth is returned if its rule is present in @rib.
 *
 * This iterator is an efficient version of the following loop:
 *
 * int i;
 * for (i = 0; i <= @depth; i++) {
 *	uint32_t next_hop;
 *	if (rib_is_rule_present(rib, address, i, &next_hop) != 1)
 *		continue;
 *
 *	=> These entries are the ones that this iterator returns.
 * }
 *
 * @address is in network order (big endian).
 * @address == NULL is equivalent to the all-zero address.
 *
 * If the RIB changes (i.e. rules are added or deleted)
 * between the call of this function and the call of
 * rib_shorter_iterator_next(), or between two consecutive calls of
 * rib_shorter_iterator_next(), the iterator will return -EFAULT.
 */
int rib_shorter_iterator_state_init(struct rib_shorter_iterator_state *state,
	const struct rib_head *rib, const uint8_t *address, uint8_t depth);

/*
 * When a rule is found, this function updates @rule and returns zero.
 * Otherwise, this function returns -ENOENT.
 */
int rib_shorter_iterator_next(struct rib_shorter_iterator_state *state,
	struct rib_iterator_rule *rule);

/*
 * Free all resources associated to @state but the memory pointed by it.
 *
 * CAUTION: This function should only be called on initialized states.
 */
static inline void
rib_shorter_iterator_end(struct rib_shorter_iterator_state *state)
{
	/* At the current version of the code, there is nothing to do here. */
	RTE_SET_USED(state);
}

#endif /* _GATEKEEPER_GK_RIB_H_ */
