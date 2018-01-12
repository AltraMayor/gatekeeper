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

#ifndef SEQLOCK_H
#define SEQLOCK_H

/*
 * The code of this file is mostly a copy of the Linux kernel,
 * and replace the Linux spinlock with DPDK's rte_spinlock_t.
 * It supports the use of hardware memory transactions (HTM) in DPDK.
 */

#include <rte_log.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>

#include "gatekeeper_main.h"

/*
 * Reader/writer consistent mechanism without starving writers. This type of
 * lock is for data where the reader wants a consistent set of information
 * and is willing to retry if the information changes. Sequence readers which
 * never block a writer but they may have to retry if a writer is in progress
 * by detecting change in sequence number. Writers do not wait for a sequence
 * reader.
 *
 * Sequential locks may not work well for data that contains pointers, because
 * any writer could invalidate a pointer that a reader was following.
 *
 * Expected non-blocking reader usage:
 * 	do {
 *		seq = read_seqbegin(&foo);
 *		...
 *	} while (read_seqretry(&foo, seq));
 */

static inline void
__read_once_size(const volatile void *p, void *res, int size)
{
 	switch (size) {
 	case 1:
		*(uint8_t *)res = *(const volatile uint8_t*)p;
		break;

 	case 2:
		*(uint16_t *)res = *(const volatile uint16_t *)p;
		break;

	case 4:
		*(uint32_t *)res = *(const volatile uint32_t *)p;
		break;

 	case 8:
		*(uint64_t *)res = *(const volatile uint64_t *)p;
		break;

 	default:
		RTE_LOG(WARNING, GATEKEEPER,
			"seqlock: Data access exceeds word size and won't be atomic\n");
		break;
	}
}

/*
 * Prevent the compiler from merging or refetching reads or writes. The
 * compiler is also forbidden from reordering successive instances of
 * READ_ONCE (see below), but only when the compiler is aware of some
 * particular ordering.  One way to make the compiler aware of ordering
 * is to put the two invocations of READ_ONCE in different C statements.
 *
 * READ_ONCE will also work on aggregate data types like structs or unions.
 * If the size of the accessed data type exceeds the word size of the machine
 * (e.g., 32 bits or 64 bits) READ_ONCE() will fall back to memcpy and print a
 * compile-time warning.
 *
 * Its two major use cases are: (1) Mediating communication between
 * process-level code and irq/NMI handlers, all running on the same CPU,
 * and (2) Ensuring that the compiler does not fold, spindle, or otherwise
 * mutilate accesses that either do not require ordering or that interact
 * with an explicit memory barrier or atomic instruction that provides the
 * required ordering.
 */
#define READ_ONCE(x) \
	({ union { typeof(x) __val; char __c[1]; } __u; \
	__read_once_size(&(x), __u.__c, sizeof(x)); rte_rmb(); __u.__val; })

/*
 * Version using sequence counter only.
 * This can be used when code has its own mutex protecting the
 * updating starting before the write_seqcountbeqin() and ending
 * after the write_seqcount_end().
 */
typedef struct seqcount {
	unsigned sequence;
} seqcount_t;

/*
 * __read_seqcount_begin - begin a seq-read critical section (without barrier).
 * @s: pointer to seqcount_t
 * Returns: count to be passed to read_seqcount_retry.
 *
 * __read_seqcount_begin is like read_seqcount_begin, but has no smp_rmb()
 * barrier. Callers should ensure that smp_rmb() or equivalent ordering is
 * provided before actually loading any of the variables that are to be
 * protected in this critical section.
 *
 * Use carefully, only in critical code, and comment how the barrier is
 * provided.
 */
static inline unsigned
__read_seqcount_begin(const seqcount_t *s)
{
	unsigned ret;

repeat:
	ret = READ_ONCE(s->sequence);
	if (unlikely(ret & 1)) {
		rte_pause();
		goto repeat;
	}
	return ret;
}

/*
 * read_seqcount_begin - begin a seq-read critical section.
 * @s: pointer to seqcount_t
 * Returns: count to be passed to read_seqcount_retry.
 *
 * read_seqcount_begin opens a read critical section of the given seqcount.
 * Validity of the critical section is tested by checking read_seqcount_retry
 * function.
 */
static inline unsigned
read_seqcount_begin(const seqcount_t *s)
{
	unsigned ret = __read_seqcount_begin(s);
	rte_smp_rmb();
	return ret;
}

/*
 * __read_seqcount_retry - end a seq-read critical section (without barrier).
 * @s: pointer to seqcount_t
 * @start: count, from read_seqcount_begin
 * Returns: 1 if retry is required, else 0.
 *
 * __read_seqcount_retry is like read_seqcount_retry, but has no smp_rmb()
 * barrier. Callers should ensure that smp_rmb() or equivalent ordering is
 * provided before actually loading any of the variables that are to be
 * protected in this critical section.
 *
 * Use carefully, only in critical code, and comment how the barrier is
 * provided.
 */
static inline int
__read_seqcount_retry(const seqcount_t *s, unsigned start)
{
	return unlikely(s->sequence != start);
}

/*
 * read_seqcount_retry - end a seq-read critical section.
 * @s: pointer to seqcount_t
 * @start: count, from read_seqcount_begin
 * Returns: 1 if retry is required, else 0.
 *
 * read_seqcount_retry closes a read critical section of the given seqcount.
 * If the critical section was invalid, it must be ignored (and typically
 * retried).
 */
static inline int
read_seqcount_retry(const seqcount_t *s, unsigned start)
{
	rte_smp_rmb();
	return __read_seqcount_retry(s, start);
}

static inline void
write_seqcount_begin(seqcount_t *s)
{
	s->sequence++;
	rte_smp_wmb();
}

static inline void
write_seqcount_end(seqcount_t *s)
{
	rte_smp_wmb();
	s->sequence++;
}

typedef struct {
	struct seqcount seqcount;
	rte_spinlock_t  lock;
} seqlock_t;

static inline void
seqlock_init(seqlock_t *sl) {
	sl->seqcount.sequence = 0;
	rte_spinlock_init(&sl->lock);
}

/*
 * Read side functions for starting and finalizing a read side section.
 */
static inline unsigned
read_seqbegin(const seqlock_t *sl)
{
	return read_seqcount_begin(&sl->seqcount);
}

static inline unsigned
read_seqretry(const seqlock_t *sl, unsigned start)
{
	return read_seqcount_retry(&sl->seqcount, start);
}

/*
 * Lock out other writers and update the count.
 * Acts like a normal spin_lock/unlock.
 */
static inline void
write_seqlock(seqlock_t *sl)
{
	rte_spinlock_lock_tm(&sl->lock);
	write_seqcount_begin(&sl->seqcount);
}

static inline void
write_sequnlock(seqlock_t *sl)
{
	write_seqcount_end(&sl->seqcount);
	rte_spinlock_unlock_tm(&sl->lock);
}

#endif /* SEQLOCK_H */
