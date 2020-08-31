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

#include <arpa/inet.h>
#include <string.h>

#include <rte_log.h>
#include <rte_debug.h>

#include "gatekeeper_lpm.h"
#include "gatekeeper_main.h"

struct rte_lpm *
init_ipv4_lpm(const char *tag,
	const struct rte_lpm_config *lpm_conf,
	unsigned int socket_id, unsigned int lcore, unsigned int identifier)
{
	int ret;
	char lpm_name[128];
	struct rte_lpm *lpm;

	ret = snprintf(lpm_name, sizeof(lpm_name),
		"%s_lpm_ipv4_%u_%u", tag, lcore, identifier);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(lpm_name));

	lpm = rte_lpm_create(lpm_name, socket_id, lpm_conf);
	if (lpm == NULL) {
		G_LOG(ERR,
			"lpm: unable to create the IPv4 LPM table %s on socket %u\n",
			lpm_name, socket_id);
		return NULL;
	}

	return lpm;
}

/*
 * Notes:
 *  - @ip should be in network order.
 *  - Callers should check for -ENOENT and log
 *    a context-specific message.
 */
int
lpm_lookup_ipv4(struct rte_lpm *lpm, uint32_t ip)
{
	int ret;
	uint32_t next_hop;

	ret = rte_lpm_lookup(lpm, ntohl(ip), &next_hop);
	if (ret == -EINVAL) {
		G_LOG(ERR, "lpm: incorrect arguments for IPv4 lookup\n");
		return ret;
	} else if (ret == -ENOENT) {
		/*
		 * Failing to find an LPM entry can mean many different
		 * things, depending on the caller. In some cases,
		 * failing to find an entry is used as a validation of
		 * the table, and is therefore not even an error.
		 *
		 * Failing to find an entry can also occur frequently
		 * on the hot path when under attack.
		 *
		 * For these reasons, we are careful about how we log the
		 * fact that the lookup failed to find an entry. We use the
		 * DEBUG level and guess whether the entry will actually be
		 * logged. Callers are encouraged to check for -ENOENT and
		 * make their own log entries as needed.
		 */
		char buf[INET_ADDRSTRLEN];

		if (likely(!G_LOG_CHECK(DEBUG)))
			return ret;

		if (likely(inet_ntop(AF_INET, &ip,
				buf, sizeof(buf)) != NULL)) {
			G_LOG(DEBUG,
				"lpm: IPv4 lookup miss for %s\n", buf);
			return ret;
		}

		G_LOG(DEBUG,
			"lpm: IPv4 lookup miss; can't convert IP to string: %s\n",
			strerror(errno));
		return ret;
	}

	RTE_VERIFY(ret == 0);
	return next_hop;
}

struct rte_lpm6 *
init_ipv6_lpm(const char *tag,
	const struct rte_lpm6_config *lpm6_conf,
	unsigned int socket_id, unsigned int lcore, unsigned int identifier)
{
	int ret;
	char lpm_name[128];
	struct rte_lpm6 *lpm;

	ret = snprintf(lpm_name, sizeof(lpm_name),
		"%s_lpm_ipv6_%u_%u", tag, lcore, identifier);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(lpm_name));

	lpm = rte_lpm6_create(lpm_name, socket_id, lpm6_conf);
	if (lpm == NULL) {
		G_LOG(ERR,
			"lpm: unable to create the IPv6 LPM table %s on socket %u\n",
			lpm_name, socket_id);
		return NULL;
	}

	return lpm;
}

/*
 * Note:
 *  - Callers should check for -ENOENT and log
 *    a context-specific message.
 */
int
lpm_lookup_ipv6(struct rte_lpm6 *lpm, struct in6_addr *ip)
{
	int ret;
	uint32_t next_hop;

	ret = rte_lpm6_lookup(lpm, (uint8_t *)ip, &next_hop);
	if (ret == -EINVAL) {
		G_LOG(ERR, "lpm: incorrect arguments for IPv6 lookup\n");
		return ret;
	} else if (ret == -ENOENT) {
		/* See comment for -ENOENT case in lpm_lookup_ipv4(). */
		char buf[INET6_ADDRSTRLEN];

		if (likely(!G_LOG_CHECK(DEBUG)))
			return ret;

		if (likely(inet_ntop(AF_INET6, &ip->s6_addr,
				buf, sizeof(buf)) != NULL)) {
			G_LOG(DEBUG,
				"lpm: IPv6 lookup miss for %s\n", buf);
			return ret;
		}

		G_LOG(DEBUG,
			"lpm: IPv6 lookup miss; can't convert IP to string: %s\n",
			strerror(errno));
		return ret;
	}

	RTE_VERIFY(ret == 0);
	return next_hop;
}
