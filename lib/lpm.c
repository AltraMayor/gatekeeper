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
		RTE_LOG(ERR, GATEKEEPER,
			"Unable to create the IPv4 LPM table %s on socket %u!\n",
			lpm_name, socket_id);
		return NULL;
	}

	return lpm;
}

/* @ip should be in network order. */
int
lpm_lookup_ipv4(struct rte_lpm *lpm, uint32_t ip)
{
	int ret;
	uint32_t next_hop;

	ret = rte_lpm_lookup(lpm, ntohl(ip), &next_hop);
	if (ret == -EINVAL) {
		RTE_LOG(ERR, LPM,
			"lpm: incorrect arguments for IPv4 lookup!\n");
		ret = -1;
		goto out;
	} else if (ret == -ENOENT) {
		RTE_LOG(WARNING, LPM, "lpm: IPv4 lookup miss!\n");
		ret = -1;
		goto out;
	}

	ret = next_hop;

out:
	return ret;
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
		RTE_LOG(ERR, GATEKEEPER,
			"Unable to create the IPv6 LPM table %s on socket %u!\n",
			lpm_name, socket_id);
		return NULL;
	}

	return lpm;
}

int
lpm_lookup_ipv6(struct rte_lpm6 *lpm, uint8_t *ip)
{
	int ret;
	uint32_t next_hop;

	ret = rte_lpm6_lookup(lpm, ip, &next_hop);
	if (ret == -EINVAL) {
		RTE_LOG(ERR, LPM,
			"lpm: incorrect arguments for IPv6 lookup!\n");
		ret = -1;
		goto out;
	} else if (ret == -ENOENT) {
		RTE_LOG(WARNING, LPM, "lpm: IPv6 lookup miss!\n");
		ret = -1;
		goto out;
	}

	ret = next_hop;

out:
	return ret;
}
