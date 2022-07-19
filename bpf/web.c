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

/*
 * This BPF program is intended as an example for a simple web server
 * that runs the services HTTP, HTTPS, SSH, and FTP.
 *
 * This BPF program builds upon the BPF program grantedv2, so
 * there are primary and secondary limits. The secondary limit is applied to
 * ICMPv4, ICMPv6, fragmented, and SYN packets.
 */

#include <net/ethernet.h>
#include <netinet/tcp.h>

#include "grantedv2.h"
#include "libicmp.h"
#include "libinet.h"

SEC("init") uint64_t
web_init(struct gk_bpf_init_ctx *ctx)
{
	return grantedv2_init_inline(ctx);
}

SEC("pkt") uint64_t
web_pkt(struct gk_bpf_pkt_ctx *ctx)
{
	struct grantedv2_state *state =
		(struct grantedv2_state *)pkt_ctx_to_cookie(ctx);
	struct rte_mbuf *pkt = pkt_ctx_to_pkt(ctx);
	uint32_t pkt_len = pkt->pkt_len;
	struct tcphdr *tcp_hdr;
	uint64_t ret = grantedv2_pkt_begin(ctx, state, pkt_len);

	if (ret != GK_BPF_PKT_RET_FORWARD) {
		/* Primary budget exceeded. */
		return ret;
	}

	/* Allowed L4 protocols. */
	switch (ctx->l4_proto) {
	case IPPROTO_ICMP:
		ret = check_icmp(ctx, pkt);
		if (ret != GK_BPF_PKT_RET_FORWARD)
			return ret;
		goto secondary_budget;

	case IPPROTO_ICMPV6:
		ret = check_icmp6(ctx, pkt);
		if (ret != GK_BPF_PKT_RET_FORWARD)
			return ret;
		goto secondary_budget;

	case IPPROTO_TCP:
		break;

	default:
		return GK_BPF_PKT_RET_DECLINE;
	}

	/*
	 * Only TCP packets from here on.
	 */

	if (ctx->fragmented)
		goto secondary_budget;
	if (pkt->l4_len < sizeof(*tcp_hdr)) {
		/* Malformed TCP header. */
		return GK_BPF_PKT_RET_DECLINE;
	}
	tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct tcphdr *,
		pkt->l2_len + pkt->l3_len);

	/*
	 * For information on active and passive modes of FTP,
	 * refer to the following page:
	 * http://slacksite.com/other/ftp.html
	 */

	/* Listening sockets. */
	switch (ntohs(tcp_hdr->th_dport)) {

	/*
	 * ATTENTION
	 *    These ports must match the one configured in the FTP
	 *    daemon. See the following page for an example:
	 *    http://slacksite.com/other/ftp-appendix1.html
	 */
	case 51000 ... 51999:	/* FTP data (passive mode) */

	case 21:	/* FTP command */
	case 80:	/* HTTP */
	case 443:	/* HTTPS */
	case 22:	/* SSH */
		if (tcp_hdr->syn) {
			if (tcp_hdr->ack) {
				/* Amplification attack. */
				return GK_BPF_PKT_RET_DECLINE;
			}
			/* Contain SYN floods. */
			goto secondary_budget;
		}
		break;

	case 20:	/* FTP data (active mode) */
		/*
		 * Accept connections of the active mode of FTP originated
		 * from our web server.
		 */
		if (tcp_hdr->syn && !tcp_hdr->ack) {
			/* All listening ports were already tested. */
			return GK_BPF_PKT_RET_DECLINE;
		}
		break;

	default:
		/* Accept connections originated from our web server. */

		if (tcp_hdr->syn && !tcp_hdr->ack) {
			/* All listening ports were already tested. */
			return GK_BPF_PKT_RET_DECLINE;
		}

		/* Authorized external services. */
		switch (ntohs(tcp_hdr->th_sport)) {
		case 80:	/* HTTP  */
		case 443:	/* HTTPS */
			break;
		default:
			return GK_BPF_PKT_RET_DECLINE;
		}
		break;
	}

	goto forward;

secondary_budget:
	ret = grantedv2_pkt_test_2nd_limit(state, pkt_len);
	if (ret != GK_BPF_PKT_RET_FORWARD)
		return ret;
forward:
	return grantedv2_pkt_end(ctx, state);
}
