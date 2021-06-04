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

#ifndef _GATEKEEPER_CPS_NETLINK_H_
#define _GATEKEEPER_CPS_NETLINK_H_

#include "gatekeeper_cps.h"

/* Functions to handle interactions with the routing daemon. */

int rd_alloc_coro(struct cps_config *cps_conf);
void rd_free_coro(struct cps_config *cps_conf);

int rd_event_sock_open(struct cps_config *cps_conf);
void rd_event_sock_close(struct cps_config *cps_conf);
void rd_process_events(struct cps_config *cps_conf);

#endif /* _GATEKEEPER_CPS_NETLINK_H_ */
