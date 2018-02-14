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

#ifndef _GATEKEEPER_GGU_H_
#define _GATEKEEPER_GGU_H_

#include "gatekeeper_mailbox.h"
#include "gatekeeper_net.h"
#include "gatekeeper_flow.h"

#define GGU_PD_VER1 (1)

/* Configuration for the GK-GT Unit functional block. */
struct ggu_config {
	unsigned int      lcore_id;

	/* The UDP source and destination port numbers for GGU. */
	uint16_t          ggu_src_port;
	uint16_t          ggu_dst_port;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */

	/* RX queue on the back interface. */
	uint16_t          rx_queue_back;
	struct net_config *net;
	struct gk_config  *gk;

	/* Mailbox to hold requests from other blocks. */
	struct mailbox    mailbox;
};

/*
 * Since the length of IPv6 policy is much larger than IPv4 policy,
 * to save network bandwidth, we choose to use different data structures
 * to store the in-packet policies for IPv4 and IPv6, respectively.
 *
 * Packet format: Ethernet headers + IP header + UDP header + Data.
 * In the UDP payload, the following format would save a lot of bytes
 * when there are decline decisions:
 *  v1, n1, n2, n3, n4: Each of these fields are 1-byte long.
 *  v1 is a constant indicating the version of the format, in this case 1.
 *  n1 is the number of IPv4 decline decisions.
 *  n2 is the number of IPv6 decline decisions.
 *  n3 is the number of IPv4 granted decisions.
 *  n4 is the number of IPv6 granted decisions.
 * 
 * Field v1 will enable us to change the format, incrementally update
 * the Gatekeeper servers, and incrementally update the Grantor servers.
 *
 * Notice that, to guarantee that all the accesses after struct ggu_common_hdr
 * in a packet are 32-bit aligned, we add uint8_t reserved[3]; at the very end
 * of struct ggu_common_hdr.
 */
struct ggu_common_hdr {
	uint8_t v1;
	uint8_t n1;
	uint8_t n2;
	uint8_t n3;
	uint8_t n4;
	uint8_t reserved[3];
}__attribute__((packed));

struct ggu_policy {
	uint8_t  state;
	struct ip_flow flow;

	struct {
		/*
		 * XXX Add state fields for the flow if necessary.
		 * The policy decision sent to a GK block must have
		 * enough information to fill out the fields of
		 * struct flow_entry at the corresponding state.
		 */
		union {
			struct {
				/* Rate limit: kilobyte/second. */
				uint32_t tx_rate_kb_sec;
				/*
				 * How much time (unit: second) a GK block waits
				 * before it expires the capability.
				 */
				uint32_t cap_expire_sec;
				/*
				 * The first value of send_next_renewal_at at
				 * flow entry comes from next_renewal_ms.
				 */
				uint32_t next_renewal_ms;
				/*
				 * How many milliseconds (unit) GK must wait
				 * before sending the next capability renewal
				 * request.
				 */
				uint32_t renewal_step_ms;
			} granted;

			struct {
				/*
				 * How much time (unit: second) a GK block waits
				 * before it expires the declined capability.
				 */
				uint32_t expire_sec;
			} declined;
		} u;
	}__attribute__((packed)) params;
};

struct ggu_config *alloc_ggu_conf(void);
int run_ggu(struct net_config *net_conf,
	struct gk_config *gk_conf, struct ggu_config *ggu_conf);
int cleanup_ggu(struct ggu_config *ggu_conf);

#endif /* _GATEKEEPER_GGU_H_ */
