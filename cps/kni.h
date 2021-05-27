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

#ifndef _GATEKEEPER_CPS_KNI_H_
#define _GATEKEEPER_CPS_KNI_H_

#include <rte_kni.h>

#include "gatekeeper_net.h"

struct arp_request {
	struct list_head list;
	uint32_t         addr;
	int              stale;
};

struct nd_request {
	struct list_head list;
	uint8_t          addr[16];
	int              stale;
};

int kni_disable_change_mtu(uint16_t port_id, unsigned int new_mtu);
int kni_change_if(uint16_t port_id, uint8_t if_up);
int kni_disable_change_mac_address(uint16_t port_id, uint8_t *mac_addr);
int kni_disable_change_promiscusity(uint16_t port_id, uint8_t to_on);
int kni_config_ip_addrs(struct rte_kni *kni, unsigned int kni_index,
	struct gatekeeper_if *iface);
int kni_config_link(struct rte_kni *kni);
int init_kni(const char *kni_kmod_path, unsigned int num_kni);
void rm_kni(void);

void kni_process_arp(struct cps_config *cps_conf, struct gatekeeper_if *iface,
	struct rte_mbuf *buf, const struct rte_ether_hdr *eth_hdr);
void kni_process_nd(struct cps_config *cps_conf, struct gatekeeper_if *iface,
	struct rte_mbuf *buf, const struct rte_ether_hdr *eth_hdr,
	uint16_t pkt_len);

#endif /* _GATEKEEPER_CPS_KNI_H_ */
