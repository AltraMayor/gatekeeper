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

#ifndef _GATEKEEPER_CPS_KNI_H_
#define _GATEKEEPER_CPS_KNI_H_

#include "gatekeeper_net.h"
#include "gatekeeper_cps.h"

int kni_create(struct cps_kni *kni, const struct gatekeeper_if *iface,
	struct rte_mempool *mp, uint16_t queue_size);

void kni_free(struct cps_kni *kni);

static inline uint16_t
kni_rx_burst(const struct cps_kni *kni, struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts)
{
	return rte_eth_rx_burst(kni->cps_portid, 0, rx_pkts, nb_pkts);
}

static inline uint16_t
kni_tx_burst(const struct cps_kni *kni, struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	return rte_eth_tx_burst(kni->cps_portid, 0, tx_pkts, nb_pkts);
}

static inline const char *
kni_get_krnname(const struct cps_kni *kni)
{
	return kni->krn_name;
}

static inline unsigned int
kni_get_ifindex(const struct cps_kni *kni)
{
	return kni->krn_ifindex;
}

#endif /* _GATEKEEPER_CPS_KNI_H_ */
