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

#define GGU_PD_VER (1)

/* Configuration for the GK-GT Unit functional block. */
struct ggu_config {
	unsigned int      lcore_id;

	/* The UDP source and destination port numbers for GGU. */
	uint16_t          ggu_src_port;
	uint16_t          ggu_dst_port;

	/* The maximum number of packets to retrieve/transmit. */
	uint16_t          max_pkt_burst;

	/* Parameters to setup the mailbox instance. */
	unsigned int      mailbox_max_entries_exp;
	unsigned int      mailbox_mem_cache_size;
	unsigned int      mailbox_burst_size;

	/* Log level for GK-GT Unit block. */
	uint32_t          log_level;
	/* Dynamic logging type, assigned at runtime. */
	int               log_type;
	/* Log ratelimit interval in ms for GK-GT Unit block. */
	uint32_t          log_ratelimit_interval_ms;
	/* Log ratelimit burst size for GK-GT Unit block. */
	uint32_t          log_ratelimit_burst;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */

	/* The maximum number of packets submitted to GGU mailbox. */
	uint16_t          mailbox_max_pkt_burst;

	/* RX queue on the back interface. */
	uint16_t          rx_queue_back;
	struct net_config *net;
	struct gk_config  *gk;

	/* Mailbox to hold requests from other blocks. */
	struct mailbox    mailbox;
};

/* Enumeration of policy decisions the GGU block can process. */
enum {
	/* Decline an IPv4 flow. */
	GGU_DEC_IPV4_DECLINED = 0,
	/* Decline an IPv6 flow. */
	GGU_DEC_IPV6_DECLINED,
	/* Grant an IPv4 flow. */
	GGU_DEC_IPV4_GRANTED,
	/* Grant an IPv6 flow. */
	GGU_DEC_IPV6_GRANTED,
	__MAX_GGU_DEC
};

/* On the wire policy decision to be processed by the GGU. */
struct ggu_decision {
	/* The policy decision type. */
	uint8_t  type;
	/* Reserved for alignment. */
	uint8_t  res1;
	uint16_t res2;

	/* The IP flow relevant to this policy decision. */
	uint8_t  ip_flow[0];

	/* Parameters for this policy decision would follow the IP flow. */
} __attribute__((packed));

/*
 * Packets that flow between the GT block and the GGU.
 * 
 * Packet format: Ethernet header(s) + IP header + UDP header + Data.
 * The UDP payload data is of the following format:
 *
 *  version: a constant indicating the version of the format, in this case 1.
 *  res1 and res2: reserved space to keep the fields 32-bit aligned.
 *  [policy decision(s)]: a list of one or more policy decisions.
 * 
 * Each policy decision (struct ggu_decision) is of the following format:
 *  
 * +---------------------------------+
 * |  Type  |  Res1  |      Res2     |
 * +---------------------------------+
 * |                                 |
 * |  IP flow (source, destination)  |
 * |                                 |
 * +---------------------------------+
 * |                                 |
 * |        Decision Parameters      |
 * |                ...              |
 * +---------------------------------+
 *
 * The decision type is from an enumerated set that both the GT block
 * and the GGU must understand in order for the decision to be
 * processed. For example, an action may grant an IPv4 flow.
 *
 * The IP flow is either a combination of two IPv4 addresses or two
 * IPv6 addresses to represent a (source, destination) flow.
 *
 * Each decision optionally ends with decision-specific parameters.
 */
struct ggu_common_hdr {
	/* Version of packet format. */
	uint8_t version;
	/* Reserved for alignment. */
	uint8_t res1;
	uint16_t res2;

	/* List of one or more policy decisions. */
	struct ggu_decision decisions[0];
} __attribute__((packed));

/* Parameters for declaring a flow granted. */
struct ggu_granted {
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
} __attribute__ ((packed));

/* Parameters for declaring a flow declined. */
struct ggu_declined {
	/*
	 * How much time (unit: second) a GK block waits
	 * before it expires the declined capability.
	 */
	uint32_t expire_sec;
} __attribute__ ((packed));

struct ggu_policy {
	uint8_t state;
	struct ip_flow flow;

	/*
	 * The policy decision sent to a GK block must have
	 * enough information to fill out the fields of
	 * struct flow_entry at the corresponding state.
	 */
	union {
		/* Decision is to grant the flow. */
		struct ggu_granted granted;
		/* Decision is to decline the flow. */
		struct ggu_declined declined;
	} params;
};

/*
 * When iterating over policy decisions in a GGU packet, this
 * function can be applied to the policy and some argument.
 * A function of this type should be passed to ggu_policy_iterator().
 */
typedef void (*ggu_policy_fn)(struct ggu_policy *policy, void *arg);

/*
 * Iterate over a GGU notification packet's decision list, beginning
 * with @ggu_decision and extending throughout @decision_list_len.
 *
 * For each policy decision found, apply @policy_fn to it along
 * with an optional @policy_arg.
 */
void ggu_policy_iterator(struct ggu_decision *ggu_decision,
	unsigned int decision_list_len, ggu_policy_fn policy_fn,
	void *policy_arg, const char *block);

struct ggu_config *alloc_ggu_conf(void);
int run_ggu(struct net_config *net_conf,
	struct gk_config *gk_conf, struct ggu_config *ggu_conf);
int cleanup_ggu(struct ggu_config *ggu_conf);

#endif /* _GATEKEEPER_GGU_H_ */
