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

#include <rte_hash.h>

#include <gatekeeper_lls.h>
#include "cache.h"
#include "nd.h"

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC rte_jhash
#endif

/* XXX Sample parameters, need to be tested for better performance. */
#define LLS_CACHE_BURST_SIZE (32)

static void
lls_send_request(struct lls_config *lls_conf, struct lls_cache *cache,
	const uint8_t *ip_be, const struct ether_addr *ha)
{
	struct gatekeeper_if *front = &lls_conf->net->front;
	struct gatekeeper_if *back = &lls_conf->net->back;
	if (cache->iface_enabled(lls_conf->net, front) &&
			cache->ip_in_subnet(front, ip_be))
		cache->xmit_req(&lls_conf->net->front, ip_be, ha,
			lls_conf->tx_queue_front);
	if (cache->iface_enabled(lls_conf->net, back) &&
			cache->ip_in_subnet(back, ip_be))
		cache->xmit_req(&lls_conf->net->back, ip_be, ha,
			lls_conf->tx_queue_back);
}

static void
lls_cache_dump(struct lls_cache *cache)
{
	uint32_t iter = 0;
	int32_t index;
	const void *key;
	void *data;

	RTE_LOG(INFO, GATEKEEPER, "LLS cache (%s)\n=====================\n",
		cache->name);
	index = rte_hash_iterate(cache->hash, &key, &data, &iter);
	while (index >= 0) {
		cache->print_record(cache, &cache->records[index]);
		index = rte_hash_iterate(cache->hash, &key, &data, &iter);
	}
}

static void
lls_update_subscribers(struct lls_record *record)
{
	unsigned int i;
	for (i = 0; i < record->num_holds; i++) {
		int call_again = false;

		record->holds[i].cb(&record->map, record->holds[i].arg,
			LLS_REPLY_RESOLUTION, &call_again);

		if (call_again)
			continue;

		/* Delete hold; keep all holds in beginning of array. */
		record->num_holds--;
		if (i < record->num_holds) {
			rte_memcpy(&record->holds[i],
				&record->holds[record->num_holds],
				sizeof(record->holds[i]));
			/*
			 * This cancels out the update of the for loop so we
			 * can redo update of hold at position @i, if needed.
			 */
			i--;
		}
	}
}

static int
lls_add_record(struct lls_cache *cache, const uint8_t *ip_be)
{
	int ret = rte_hash_add_key(cache->hash, ip_be);
	if (unlikely(ret == -EINVAL || ret == -ENOSPC)) {
		char ip_buf[cache->key_str_len];
		char *ip_str = cache->ip_str(cache, ip_be,
			ip_buf, cache->key_str_len);
		RTE_LOG(ERR, HASH, "%s, could not add record for %s\n",
			ret == -EINVAL ? "Invalid params" : "No space",
			ip_str == NULL ? cache->name : ip_str);
	} else
		RTE_VERIFY(ret >= 0);
	return ret;
}

static void
lls_del_record(struct lls_cache *cache, const uint8_t *ip_be)
{
	int32_t ret = rte_hash_del_key(cache->hash, ip_be);
	if (unlikely(ret == -ENOENT || ret == -EINVAL)) {
		char ip_buf[cache->key_str_len];
		char *ip_str = cache->ip_str(cache, ip_be, ip_buf,
			cache->key_str_len);
		RTE_LOG(ERR, HASH, "%s, record for %s not deleted\n",
			ret == -ENOENT ? "No map found" : "Invalid params",
			ip_str == NULL ? cache->name : ip_str);
	}
}

static void
lls_process_hold(struct lls_config *lls_conf, struct lls_hold_req *hold_req)
{
	struct lls_cache *cache = hold_req->cache;
	struct lls_record *record;
	int ret = rte_hash_lookup(cache->hash, hold_req->ip_be);

	if (ret == -ENOENT) {
		ret = lls_add_record(cache, hold_req->ip_be);
		if (ret < 0)
			return;

		record = &cache->records[ret];
		record->map.stale = true;
		rte_memcpy(record->map.ip_be, hold_req->ip_be, cache->key_len);
		record->ts = time(NULL);
		RTE_VERIFY(record->ts >= 0);
		record->holds[0] = hold_req->hold;
		record->num_holds = 1;

		/* Try to resolve record using broadcast. */
		lls_send_request(lls_conf, cache, hold_req->ip_be, NULL);

		if (lls_conf->debug)
			lls_cache_dump(cache);
		return;
	} else if (unlikely(ret == -EINVAL)) {
		char ip_buf[cache->key_str_len];
		char *ip_str;
		ip_str = cache->ip_str(cache, hold_req->ip_be, ip_buf,
			cache->key_str_len);
		RTE_LOG(ERR, HASH,
			"Invalid params, could not get %s map; hold failed\n",
			ip_str == NULL ? cache->name : ip_str);
		return;
	}

	RTE_VERIFY(ret >= 0);
	record = &cache->records[ret];

	if (!record->map.stale) {
		int call_again = false;
		/* Alert requester this map is ready. */
		hold_req->hold.cb(&record->map, hold_req->hold.arg,
			LLS_REPLY_RESOLUTION, &call_again);
		if (!call_again)
			return;
	}
	record->holds[record->num_holds++] = hold_req->hold;

	if (lls_conf->debug)
		lls_cache_dump(cache);
}

static void
lls_process_put(struct lls_config *lls_conf, struct lls_put_req *put_req)
{
	struct lls_cache *cache = put_req->cache;
	struct lls_record *record;
	unsigned int i;
	int ret = rte_hash_lookup(cache->hash, put_req->ip_be);

	if (ret == -ENOENT) {
		/*
		 * Not necessarily an error: the block may have indicated
		 * it did not want its callback to be called again, and
		 * all holds have been released on that entry.
		 */
		return;
	} else if (unlikely(ret == -EINVAL)) {
		char ip_buf[cache->key_str_len];
		char *ip_str = cache->ip_str(cache, put_req->ip_be, ip_buf,
			cache->key_str_len);
		RTE_LOG(ERR, HASH,
			"Invalid params, could not get %s map; put failed\n",
			ip_str == NULL ? cache->name : ip_str);
		return;
	}

	RTE_VERIFY(ret >= 0);
	record = &cache->records[ret];

	for (i = 0; i < record->num_holds; i++) {
		if (put_req->lcore_id == record->holds[i].lcore_id)
			break;
	}

	/* Requesting lcore not found in holds. */
	if (i == record->num_holds)
		return;

	/*
	 * Alert the requester that its hold will be removed, so it
	 * may free any state that is keeping track of that hold.
	 *
	 * Technically the hold will be removed in the step
	 * below, but alerting the requester first removes the need
	 * to copy the hold into a temporary variable, remove
	 * the hold from record->holds, and then alert the
	 * requester using the temporary variable. This is OK since
	 * there's only one writer.
	 */
	record->holds[i].cb(&record->map, record->holds[i].arg,
		LLS_REPLY_FREE, NULL);

	/* Keep all holds in beginning of array. */
	record->num_holds--;
	if (i < record->num_holds)
		rte_memcpy(&record->holds[i], &record->holds[record->num_holds],
			sizeof(record->holds[i]));

	if (lls_conf->debug)
		lls_cache_dump(cache);
}

void
lls_process_mod(struct lls_config *lls_conf, struct lls_mod_req *mod_req)
{
	struct lls_cache *cache = mod_req->cache;
	struct lls_record *record;
	int changed_ha = false;
	int changed_port = false;
	int changed_stale = false;
	int ret = rte_hash_lookup(cache->hash, mod_req->ip_be);

	if (ret == -ENOENT) {
		ret = lls_add_record(cache, mod_req->ip_be);
		if (ret < 0)
			return;

		/* Fill-in new record. */
		record = &cache->records[ret];
		ether_addr_copy(&mod_req->ha, &record->map.ha);
		record->map.port_id = mod_req->port_id;
		record->map.stale = false;
		rte_memcpy(record->map.ip_be, mod_req->ip_be, cache->key_len);
		record->ts = mod_req->ts;
		record->num_holds = 0;

		if (lls_conf->debug)
			lls_cache_dump(cache);
		return;
	} else if (unlikely(ret == -EINVAL)) {
		char ip_buf[cache->key_str_len];
		char *ip_str;
		ip_str = cache->ip_str(cache, mod_req->ip_be, ip_buf,
			cache->key_str_len);
		RTE_LOG(ERR, HASH,
			"Invalid params, could not get %s map; mod failed\n",
			ip_str == NULL ? cache->name : ip_str);
		return;
	}

	RTE_VERIFY(ret >= 0);
	record = &cache->records[ret];

	if (!is_same_ether_addr(&mod_req->ha, &record->map.ha)) {
		ether_addr_copy(&mod_req->ha, &record->map.ha);
		changed_ha = true;
	}
	if (record->map.port_id != mod_req->port_id) {
		record->map.port_id = mod_req->port_id;
		changed_port = true;
	}
	if (record->map.stale) {
		record->map.stale = false;
		changed_stale = true;
	}
	record->ts = mod_req->ts;

	if (changed_ha || changed_port || changed_stale) {
		lls_update_subscribers(record);
		if (lls_conf->debug)
			lls_cache_dump(cache);
	}
}

unsigned int
lls_process_reqs(struct lls_config *lls_conf)
{
	struct lls_request *reqs[LLS_CACHE_BURST_SIZE];
	unsigned int count = mb_dequeue_burst(&lls_conf->requests,
		(void **)reqs, LLS_CACHE_BURST_SIZE);
	unsigned int i;

	for (i = 0; i < count; i++) {
		switch (reqs[i]->ty) {
		case LLS_REQ_HOLD:
			lls_process_hold(lls_conf, &reqs[i]->u.hold);
			break;
		case LLS_REQ_PUT:
			lls_process_put(lls_conf, &reqs[i]->u.put);
			break;
		case LLS_REQ_ND: {
			struct lls_nd_req *nd = &reqs[i]->u.nd;
			int i;
			for (i = 0; i < nd->num_pkts; i++) {
				if (process_nd(lls_conf, nd->iface,
						nd->pkts[i]) == -1)
					rte_pktmbuf_free(nd->pkts[i]);
			}
			break;
		}
		default:
			RTE_LOG(ERR, GATEKEEPER,
				"lls: unrecognized request type (%d)\n",
				reqs[i]->ty);
			break;
		}
		mb_free_entry(&lls_conf->requests, reqs[i]);
	}

	return count;
}

int
lls_req(enum lls_req_ty ty, void *req_arg)
{
	struct lls_config *lls_conf = get_lls_conf();
	struct lls_request *req = mb_alloc_entry(&lls_conf->requests);
	int ret;

	if (req == NULL) {
		RTE_LOG(ERR, GATEKEEPER,
			"lls: allocation for request of type %d failed", ty);
		return -1;
	}

	req->ty = ty;

	switch (ty) {
	case LLS_REQ_HOLD:
		req->u.hold = *(struct lls_hold_req *)req_arg;
		break;
	case LLS_REQ_PUT:
		req->u.put = *(struct lls_put_req *)req_arg;
		break;
	case LLS_REQ_ND:
		req->u.nd = *(struct lls_nd_req *)req_arg;
		break;
	default:
		mb_free_entry(&lls_conf->requests, req);
		RTE_LOG(ERR, GATEKEEPER,
			"lls: unknown request type %d failed", ty);
		return -1;
	}

	ret = mb_send_entry(&lls_conf->requests, req);
	if (ret < 0)
		return ret;

	return 0;
}

struct lls_map *
lls_cache_get(struct lls_cache *cache, const uint8_t *ip_be)
{
	int ret = rte_hash_lookup(cache->hash, ip_be);
	if (ret < 0)
		return NULL;
	return &cache->records[ret].map;
}

void
lls_cache_scan(struct lls_config *lls_conf, struct lls_cache *cache)
{
	uint32_t iter = 0;
	int32_t index;
	const uint8_t *ip_be;
	void *data;
	struct gatekeeper_if *front = &lls_conf->net->front;
	struct gatekeeper_if *back = &lls_conf->net->back;
	time_t now = time(NULL);

	RTE_VERIFY(now >= 0);
	index = rte_hash_iterate(cache->hash, (void *)&ip_be, &data, &iter);
	while (index >= 0) {
		struct lls_record *record = &cache->records[index];
		uint32_t timeout;

		/*
		 * If a map is already stale, continue to
		 * try to resolve it while there's interest.
		 */
		if (record->map.stale) {
			if (record->num_holds > 0)
				lls_send_request(lls_conf, cache, ip_be, NULL);
			else
				lls_del_record(cache, ip_be);
			goto next;
		}

		if (record->map.port_id == front->id)
			timeout = cache->front_timeout_sec;
		else if (lls_conf->net->back_iface_enabled &&
				record->map.port_id == back->id)
			timeout = cache->back_timeout_sec;
		else {
			char ip_buf[cache->key_str_len];
			char *ip_str = cache->ip_str(cache, ip_be, ip_buf,
				cache->key_str_len);
			RTE_LOG(ERR, GATEKEEPER,
				"lls: map for %s has an invalid port %hhu\n",
				ip_str == NULL ? cache->name : ip_str,
				record->map.port_id);
			lls_del_record(cache, ip_be);
			goto next;
		}

		if (now - record->ts >= timeout) {
			record->map.stale = true;
			lls_update_subscribers(record);
			if (record->num_holds > 0)
				lls_send_request(lls_conf, cache, ip_be,
					&record->map.ha);
		} else if (timeout > LLS_CACHE_SCAN_INTERVAL &&
				(now - record->ts >=
					timeout - LLS_CACHE_SCAN_INTERVAL)) {
			/*
			 * If the record is close to being stale,
			 * preemptively send a unicast probe.
			 */
			if (record->num_holds > 0)
				lls_send_request(lls_conf, cache, ip_be,
					&record->map.ha);
		}
next:
		index = rte_hash_iterate(cache->hash, (void *)&ip_be,
			&data, &iter);
	}

	if (get_lls_conf()->debug)
		lls_cache_dump(cache);
}

void
lls_cache_destroy(struct lls_cache *cache)
{
	rte_hash_free(cache->hash);
}

int
lls_cache_init(struct lls_config *lls_conf, struct lls_cache *cache)
{
	struct rte_hash_parameters lls_cache_params = {
		.name = cache->name,
		.entries = LLS_CACHE_RECORDS,
		.reserved = 0,
		.key_len = cache->key_len,
		.hash_func = DEFAULT_HASH_FUNC,
		.hash_func_init_val = 0,
		.socket_id = rte_lcore_to_socket_id(lls_conf->lcore_id),
		.extra_flag = 0,
	};

	RTE_VERIFY(cache->key_len <= LLS_MAX_KEY_LEN);
	cache->hash = rte_hash_create(&lls_cache_params);
	if (cache->hash == NULL) {
		RTE_LOG(ERR, HASH, "Could not create %s cache hash\n",
			cache->name);
		return -1;
	}
	return 0;
}
