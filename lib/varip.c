#include <rte_ip.h>
#include <rte_mbuf.h>

#include "gatekeeper_varip.h"

/* NextHeader field of IPv6 header. */

/* Hop-by-hop option header. */
#define NEXTHDR_HOP      (0)

/* Routing header. */
#define NEXTHDR_ROUTING  (43)

/* Fragmentation/reassembly header. */
#define NEXTHDR_FRAGMENT (44)

/* Authentication header. */
#define NEXTHDR_AUTH     (51)

/* No next header. */
#define NEXTHDR_NONE     (59)

/* Destination options header. */
#define NEXTHDR_DEST     (60)

static inline bool
ipv6_ext_hdr(uint8_t nexthdr)
{
	/* Find out if nexthdr is an extension header or a protocol. */
	return (nexthdr == NEXTHDR_HOP) ||
		(nexthdr == NEXTHDR_ROUTING) ||
		(nexthdr == NEXTHDR_FRAGMENT) ||
		(nexthdr == NEXTHDR_AUTH) ||
		(nexthdr == NEXTHDR_NONE) ||
		(nexthdr == NEXTHDR_DEST);
}

struct ipv6_opt_hdr {
	uint8_t nexthdr;
	uint8_t hdrlen;
} __attribute__((packed));

int
ipv6_skip_exthdr(const struct rte_ipv6_hdr *ip6hdr,
	int remaining_len, uint8_t *nexthdrp)
{
	int start = sizeof(struct rte_ipv6_hdr);
	uint8_t nexthdr = ip6hdr->proto;

	while (ipv6_ext_hdr(nexthdr)) {
		int hdrlen;
		const struct ipv6_opt_hdr *hp;

		if (start + (int)sizeof(struct ipv6_opt_hdr) > remaining_len)
			return -EINVAL;

		hp = (const struct ipv6_opt_hdr *)
			((const uint8_t *)ip6hdr + start);

		switch (nexthdr) {
		case NEXTHDR_NONE:
			return -EINVAL;
			break;

		case NEXTHDR_FRAGMENT:
			hdrlen = 8;
			break;

		case NEXTHDR_AUTH:
			hdrlen = ((hp->hdrlen + 2) << 2);
			break;

		default:
			hdrlen = ((hp->hdrlen + 1) << 3);
			break;
		}

		nexthdr = hp->nexthdr;
		start += hdrlen;

		if (start > remaining_len)
			return -EINVAL;
	}

	*nexthdrp = nexthdr;
	return start;
}
