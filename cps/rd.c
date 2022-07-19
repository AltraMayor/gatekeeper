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

#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/if_arp.h>

#include <rte_kni.h>

#include "rd.h"

/* Defined in the kernel headers, but not included in net/if.h. */
#define IFF_LOWER_UP (1<<16)

struct route_update {
	/* Type of route update: RTM_NEWROUTE or RTM_DELROUTE. */
	int      type;

	/* Address family of route: AF_INET or AF_INET6. */
	int      family;

	/*
	 * Whether this update has all the fields and attributes
	 * necessary to update the LPM table.
	 */
	int      valid;

	/* Route type. See field rtm_type of struct rtmsg. */
	uint8_t  rt_type;

	/* Properties of the route to be saved in the FIB. */
	struct route_properties rt_props;

	/*
	 * Flags over the update request.
	 * See field nlmsg_flags of struct nlmsghdr.
	 */
	unsigned int rt_flags;

	/* Output interface index of route. */
	uint32_t oif_index;

	/* The network prefix (destination) of route. */
	char ip_px_buf[INET6_ADDRSTRLEN + 4];
	struct ip_prefix prefix_info;

	/* IP address of route gateway. */
	char gw_buf[INET6_ADDRSTRLEN];
	struct ipaddr gw;
};

void
rd_event_sock_close(struct cps_config *cps_conf)
{
	if (cps_conf->rd_nl != NULL) {
		mnl_socket_close(cps_conf->rd_nl);
		cps_conf->rd_nl = NULL;
	}
}

int
rd_event_sock_open(struct cps_config *cps_conf)
{
	struct mnl_socket *nl;
	int ret;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		G_LOG(ERR, "%s: mnl_socket_open: %s\n",
			__func__, strerror(errno));
		return -1;
	}
	cps_conf->rd_nl = nl;

	/*
	 * This binds the Netlink socket to port @nl_pid,
	 * so the routing daemon may interact with Gatekeeper.
	 */
	ret = mnl_socket_bind(nl, 0, cps_conf->nl_pid);
	if (ret < 0) {
		G_LOG(ERR, "%s: mnl_socket_bind: %s\n",
			__func__, strerror(errno));
		goto close;
	}

	return 0;

close:
	rd_event_sock_close(cps_conf);
	return ret;
}

static int
get_prefix_fib(struct route_update *update, struct gk_lpm *ltbl,
	struct gk_fib **prefix_fib)
{
	uint32_t fib_id;
	int ret;

	if (update->family == AF_INET) {
		ret = lpm_is_rule_present(ltbl->lpm,
			update->prefix_info.addr.ip.v4.s_addr,
			update->prefix_info.len, &fib_id);
		if (ret < 0) {
			G_LOG(ERR, "%s(): lpm_is_rule_present(%s) failed (%i)\n",
				__func__, update->prefix_info.str, ret);
			return ret;
		}
		if (ret == 1) {
			*prefix_fib = &ltbl->fib_tbl[fib_id];
			return 0;
		}
	} else if (likely(update->family == AF_INET6)) {
		ret = lpm6_is_rule_present(ltbl->lpm6,
			update->prefix_info.addr.ip.v6.s6_addr,
			update->prefix_info.len, &fib_id);
		if (ret < 0) {
			G_LOG(ERR, "%s(): lpm6_is_rule_present(%s) failed (%i)\n",
				__func__, update->prefix_info.str, ret);
			return ret;
		}
		if (ret == 1) {
			*prefix_fib = &ltbl->fib_tbl6[fib_id];
			return 0;
		}
	} else {
		G_LOG(ERR,
			"cps update: unknown address family %d at %s()\n",
			update->family, __func__);
		return -EAFNOSUPPORT;
	}

	RTE_VERIFY(ret == 0);
	*prefix_fib = NULL;
	return 0;
}

static int
can_rd_del_route(struct route_update *update, struct gk_fib *prefix_fib)
{
	/*
	 * Protect grantor entries from configuration mistakes
	 * in routing daemons.
	 */
	if (prefix_fib->action == GK_FWD_GRANTOR) {
		G_LOG(ERR,
			"Prefix %s cannot be updated via RTNetlink because it is a grantor entry; use the dynamic configuration block to update grantor entries\n",
			update->prefix_info.str);
		return -EPERM;
	}

	return 0;
}

static int
new_route(struct route_update *update, const struct cps_config *cps_conf)
{
	struct gk_lpm *ltbl = &cps_conf->gk->lpm_tbl;
	struct gk_fib *prefix_fib;
	int ret;

	ret = get_prefix_fib(update, ltbl, &prefix_fib);
	if (ret < 0)
		return ret;

	if (prefix_fib != NULL) {
		if ((update->rt_flags & NLM_F_EXCL) ||
			!(update->rt_flags & NLM_F_REPLACE))
			return -EEXIST;

		ret = can_rd_del_route(update, prefix_fib);
		if (ret < 0)
			return ret;

		/* Gatekeeper does not currently support multipath. */
		if (update->rt_flags & NLM_F_APPEND) {
			G_LOG(WARNING,
				"%s(%s): flag NLM_F_APPEND is NOT supported\n",
				__func__, update->ip_px_buf);
			return -EOPNOTSUPP;
		}

		/*
		 * Ignore the return of del_fib_entry_numerical() because
		 * no lock is held since the prefix lookup. Thus,
		 * the prefix may or may not be in the table.
		 */
		del_fib_entry_numerical(&update->prefix_info, cps_conf->gk);
	} else {
		if (!(update->rt_flags & NLM_F_CREATE))
			return -ENOENT;
	}

	if (update->rt_type == RTN_BLACKHOLE) {
		return add_fib_entry_numerical(&update->prefix_info, NULL,
			NULL, 0, GK_DROP, &update->rt_props, cps_conf->gk);
	}

	if (update->oif_index == 0) {
		/*
		 * Find out where the gateway is a neighbor:
		 * front or back network.
		 */
		struct gk_fib *gw_fib = NULL;

		/*
		 * Obtain @gw_fib.
		 */
		if (update->family == AF_INET) {
			ret = lpm_lookup_ipv4(ltbl->lpm,
				update->gw.ip.v4.s_addr);
			if (ret < 0) {
				if (ret == -ENOENT) {
					G_LOG(WARNING,
						"%s(): there is no route to the gateway %s of the IPv4 route %s sent by routing daemon\n",
						__func__, update->gw_buf,
						update->ip_px_buf);
				}
				return ret;
			}
			gw_fib = &ltbl->fib_tbl[ret];
		} else if (likely(update->family == AF_INET6)) {
			ret = lpm_lookup_ipv6(ltbl->lpm6, &update->gw.ip.v6);
			if (ret < 0) {
				if (ret == -ENOENT) {
					G_LOG(WARNING,
						"%s(): there is no route to the gateway %s of the IPv6 route %s sent by routing daemon\n",
						__func__, update->gw_buf,
						update->ip_px_buf);
				}
				return ret;
			}
			gw_fib = &ltbl->fib_tbl6[ret];
		} else {
			/* The execution should never reach here. */
			rte_panic("Unexpected condition in %s()\n", __func__);
		}
		RTE_VERIFY(gw_fib != NULL);

		if (gw_fib->action == GK_FWD_NEIGHBOR_FRONT_NET)
			update->oif_index = cps_conf->front_kni_index;
		else if (likely(gw_fib->action == GK_FWD_NEIGHBOR_BACK_NET))
			update->oif_index = cps_conf->back_kni_index;
		else {
			G_LOG(ERR,
				"%s(%s): the gateway %s is NOT a neighbor\n",
				__func__, update->ip_px_buf, update->gw_buf);
			return -EINVAL;
		}
	}

	if (update->oif_index == cps_conf->front_kni_index) {
		return add_fib_entry_numerical(&update->prefix_info, NULL,
			&update->gw, 1, GK_FWD_GATEWAY_FRONT_NET,
			&update->rt_props, cps_conf->gk);
	}

	if (likely(update->oif_index == cps_conf->back_kni_index)) {
		return add_fib_entry_numerical(&update->prefix_info, NULL,
			&update->gw, 1, GK_FWD_GATEWAY_BACK_NET,
			&update->rt_props, cps_conf->gk);
	}

	G_LOG(ERR,
		"%s(%s): interface %u is neither the KNI front (%u) or KNI back (%u) interface\n",
		__func__, update->ip_px_buf, update->oif_index,
		cps_conf->front_kni_index, cps_conf->back_kni_index);
	return -EINVAL;
}

static int
del_route(struct route_update *update, const struct cps_config *cps_conf)
{
	struct gk_fib *prefix_fib;

	int ret = get_prefix_fib(update, &cps_conf->gk->lpm_tbl, &prefix_fib);
	if (ret < 0)
		goto error;

	if (prefix_fib == NULL) {
		ret = -ENOENT;
		goto error;
	}

	ret = can_rd_del_route(update, prefix_fib);
	if (ret < 0)
		goto error;

	ret = del_fib_entry_numerical(&update->prefix_info, cps_conf->gk);

error:
	/*
	 * Although the Linux kernel uses ENOENT for similar situations (e.g.
	 * when RTM_NEWROUTE tries to replace an entry that does not exist),
	 * it uses ESRCH for RTM_DELROUTE.
	 */
	if (ret == -ENOENT)
		return -ESRCH;
	return ret;
}

/*
 * @addr_buf must be at least INET6_ADDRSTRLEN bytes long.
 * @addr can be NULL.
 */
static int
__convert_ip_attr(int family, struct nlattr *tb[], enum rtattr_type_t attr_type,
	const char *attr_name, struct ipaddr *addr, char *addr_buf)
{
	if (family == AF_INET) {
		const struct in_addr *addr4 =
			mnl_attr_get_payload(tb[attr_type]);
		if (addr) {
			addr->proto = RTE_ETHER_TYPE_IPV4;
			addr->ip.v4 = *addr4;
		}

		if (unlikely(inet_ntop(AF_INET, addr4, addr_buf,
				INET_ADDRSTRLEN) == NULL)) {
			int saved_errno = errno;
			G_LOG(ERR,
				"%s(%s): failed to convert an IPv4 address: %s\n",
				__func__, attr_name, strerror(errno));
			return -saved_errno;
		}

		return 0;
	}

	if (likely(family == AF_INET6)) {
		const struct in6_addr *addr6 =
			mnl_attr_get_payload(tb[attr_type]);
		if (addr) {
			addr->proto = RTE_ETHER_TYPE_IPV6;
			addr->ip.v6 = *addr6;
		}

		if (unlikely(inet_ntop(AF_INET6, addr6, addr_buf,
				INET6_ADDRSTRLEN) == NULL)) {
			int saved_errno = errno;
			G_LOG(ERR,
				"%s(%s): failed to convert an IPv6 address: %s\n",
				__func__, attr_name, strerror(errno));
			return -saved_errno;
		}

		return 0;
	}

	G_LOG(WARNING, "%s(%s): unknown address family %d\n",
			__func__, attr_name, family);
	return -EAFNOSUPPORT;
}

#define convert_ip_attr(family, tb, attr_type, addr, addr_buf)	\
	__convert_ip_attr(family, tb, attr_type, #attr_type, addr, addr_buf)

static int
attr_get(struct route_update *update, int family, struct nlattr *tb[])
{
	char addr_buf[INET6_ADDRSTRLEN];
	int ret;
	bool dst_present = false;
	bool gw_present = false;

	if (tb[RTA_MULTIPATH]) {
		/*
		 * XXX #75 This is the attribute used to implement ECMP.
		 * We should more closely parse this attribute and
		 * return the appropriate information through
		 * @update to Grantor, if we're running Grantor.
		 *
		 * Example usage:
		 *
		 * struct rtnexthop *rt =
		 *	mnl_attr_get_payload(tb[RTA_MULTIPATH]);
		 */
		G_LOG(WARNING,
			"cps update: the rtnetlink command has information (RTA_MULTIPATH) that we don't need or don't honor\n");
	}

	if (tb[RTA_DST]) {
		ret = convert_ip_attr(family, tb, RTA_DST,
			&update->prefix_info.addr, addr_buf);
		if (ret < 0)
			return ret;

		/* Fill in prefix string. */
		ret = snprintf(update->ip_px_buf, sizeof(update->ip_px_buf),
				"%s/%hhu", addr_buf, update->prefix_info.len);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(update->ip_px_buf));
		update->prefix_info.str = update->ip_px_buf;

		G_LOG(DEBUG, "cps update: dst: %s\n", update->ip_px_buf);
		dst_present = true;
	}

	if (tb[RTA_SRC]) {
		ret = convert_ip_attr(family, tb, RTA_SRC, NULL, addr_buf);
		if (ret < 0)
			return ret;

		G_LOG(WARNING,
			"cps update: the rtnetlink command has information (RTA_SRC with IP address %s) that we don't need or don't honor\n",
			addr_buf);
	}

	if (tb[RTA_OIF]) {
		update->oif_index = mnl_attr_get_u32(tb[RTA_OIF]);
		G_LOG(DEBUG, "cps update: oif=%u\n", update->oif_index);
	}

	if (tb[RTA_FLOW]) {
		G_LOG(WARNING,
			"cps update: the rtnetlink command has information (RTA_FLOW with flow=%u) that we don't need or don't honor\n",
			mnl_attr_get_u32(tb[RTA_FLOW]));
	}

	if (tb[RTA_PREFSRC]) {
		ret = convert_ip_attr(family, tb, RTA_PREFSRC, NULL, addr_buf);
		if (ret < 0)
			return ret;

		G_LOG(WARNING,
			"cps update: the rtnetlink command has information (RTA_PREFSRC with IP address %s) that we don't need or don't honor\n",
			addr_buf);
	}

	if (tb[RTA_GATEWAY]) {
		ret = convert_ip_attr(family, tb, RTA_GATEWAY,
			&update->gw, update->gw_buf);
		if (ret < 0)
			return ret;

		G_LOG(DEBUG, "cps update: gw: %s\n", update->gw_buf);
		gw_present = true;
	}

	if (tb[RTA_PRIORITY]) {
		update->rt_props.priority = mnl_attr_get_u32(tb[RTA_PRIORITY]);
		G_LOG(DEBUG, "cps update: priority = %u\n",
			update->rt_props.priority);
	}

	update->valid = dst_present && (
		(update->type == RTM_DELROUTE) ||
		(update->type == RTM_NEWROUTE && gw_present) ||
		(update->type == RTM_NEWROUTE &&
			update->rt_type == RTN_BLACKHOLE)
		);
	return 0;
}

static int
data_ipv4_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* Skip unsupported attribute in user-space. */
	if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case RTA_MULTIPATH:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0)
			return MNL_CB_ERROR;
		break;
	case RTA_TABLE:
	case RTA_DST:
	case RTA_SRC:
	case RTA_OIF:
	case RTA_FLOW:
	case RTA_PREFSRC:
	case RTA_GATEWAY:
	case RTA_PRIORITY:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			return MNL_CB_ERROR;
		break;
	default:
		/* Skip attributes we don't know about. */
		return MNL_CB_OK;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int
data_ipv6_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* Skip unsupported attribute in user-space. */
	if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case RTA_MULTIPATH:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0)
			return MNL_CB_ERROR;
		break;
	case RTA_TABLE:
	case RTA_OIF:
	case RTA_FLOW:
	case RTA_PRIORITY:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			return MNL_CB_ERROR;
		break;
	case RTA_DST:
	case RTA_SRC:
	case RTA_PREFSRC:
	case RTA_GATEWAY:
		if (mnl_attr_validate2(attr, MNL_TYPE_BINARY,
				sizeof(struct in6_addr)) < 0)
			return MNL_CB_ERROR;
		break;
	default:
		/* Skip attributes we don't know about. */
		return MNL_CB_OK;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static inline void
rd_yield(struct cps_config *cps_conf)
{
	coro_transfer(&cps_conf->coro_rd, &cps_conf->coro_root);
}

static ssize_t
sendto_with_yield(int sockfd, const void *buf, size_t len,
	const struct sockaddr *dest_addr, socklen_t addrlen,
	struct cps_config *cps_conf)
{
	ssize_t ret;
	while (
			((ret = sendto(sockfd, buf, len, MSG_DONTWAIT,
				dest_addr, addrlen)) == -1) &&
			(errno == EAGAIN || errno == EWOULDBLOCK)
			)
		rd_yield(cps_conf);
	return ret;
}

static void
rd_send_err(const struct nlmsghdr *req, struct cps_config *cps_conf, int err)
{
	struct nlmsghdr *rep;
	struct nlmsgerr *errmsg;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct sockaddr_nl rd_sa;
	unsigned int payload_len;
	unsigned int errmsg_len;

	memset(&rd_sa, 0, sizeof(rd_sa));
	rd_sa.nl_family = AF_NETLINK;
	rd_sa.nl_pid = req->nlmsg_pid;

	rep = mnl_nlmsg_put_header(buf);
	rep->nlmsg_type = NLMSG_ERROR;
	rep->nlmsg_flags = 0;
	rep->nlmsg_seq = req->nlmsg_seq;
	rep->nlmsg_pid = cps_conf->nl_pid;

	/*
	 * For acknowledgements, just send the struct nlmsgerr.
	 * For errors, send the struct nlmsgerr and the payload.
	 */
	payload_len = 0;
	errmsg_len = sizeof(*errmsg);
	if (err) {
		payload_len += mnl_nlmsg_get_payload_len(req);
		errmsg_len += payload_len;
	}

	errmsg = mnl_nlmsg_put_extra_header(rep, errmsg_len);
	errmsg->error = err;
	memcpy(&errmsg->msg, req, sizeof(errmsg->msg) + payload_len);

	if (sendto_with_yield(mnl_socket_get_fd(cps_conf->rd_nl),
			rep, sizeof(*rep) + errmsg_len,
			(struct sockaddr *)&rd_sa, sizeof(rd_sa),
			cps_conf) < 0) {
		G_LOG(ERR, "sendto_with_yield: cannot send NLMSG_ERROR to daemon (pid=%u seq=%u): %s\n",
			req->nlmsg_pid, req->nlmsg_seq, strerror(errno));
	}
}

static inline void
put_priority(struct nlmsghdr *reply, uint32_t priority)
{
	/*
	 * Not only is the default priority very common,
	 * it does not need to be reported.
	 */
	if (likely(priority == 0))
		return;

	mnl_attr_put_u32(reply, RTA_PRIORITY, priority);
}

static void
rd_fill_getroute_reply(const struct cps_config *cps_conf,
	struct nlmsghdr *reply, struct gk_fib *fib, int family, uint32_t seq,
	uint8_t prefix_len, struct ipaddr **gw_addr)
{
	struct rtmsg *rm;

	reply->nlmsg_type = RTM_NEWROUTE;
	reply->nlmsg_flags = NLM_F_MULTI;
	reply->nlmsg_seq = seq;
	reply->nlmsg_pid = cps_conf->nl_pid;

	rm = mnl_nlmsg_put_extra_header(reply, sizeof(*rm));
	rm->rtm_family = family;
	rm->rtm_dst_len = prefix_len;
	rm->rtm_src_len = 0;
	rm->rtm_tos = 0;
	rm->rtm_table = RT_TABLE_MAIN;
	rm->rtm_scope = RT_SCOPE_UNIVERSE;
	rm->rtm_flags = 0;

	switch (fib->action) {
	case GK_FWD_GRANTOR:
		mnl_attr_put_u32(reply, RTA_OIF, cps_conf->back_kni_index);
		rm->rtm_protocol = RTPROT_STATIC;
		rm->rtm_type = RTN_UNICAST;
		/*
		 * Gateway will be filled in by the caller, since Grantor
		 * entries can have multiple corresponding Grantors, each
		 * with their own gateway.
		 */
		break;
	case GK_FWD_GATEWAY_FRONT_NET:
		mnl_attr_put_u32(reply, RTA_OIF, cps_conf->front_kni_index);
		put_priority(reply, fib->u.gateway.props.priority);
		rm->rtm_protocol = fib->u.gateway.props.rt_proto;
		rm->rtm_type = RTN_UNICAST;
		*gw_addr = &fib->u.gateway.eth_cache->ip_addr;
		break;
	case GK_FWD_GATEWAY_BACK_NET:
		mnl_attr_put_u32(reply, RTA_OIF, cps_conf->back_kni_index);
		put_priority(reply, fib->u.gateway.props.priority);
		rm->rtm_protocol = fib->u.gateway.props.rt_proto;
		rm->rtm_type = RTN_UNICAST;
		*gw_addr = &fib->u.gateway.eth_cache->ip_addr;
		break;
	case GK_FWD_NEIGHBOR_FRONT_NET:
		mnl_attr_put_u32(reply, RTA_OIF, cps_conf->front_kni_index);
		rm->rtm_protocol = RTPROT_STATIC;
		rm->rtm_type = RTN_UNICAST;
		*gw_addr = NULL;
		break;
	case GK_FWD_NEIGHBOR_BACK_NET:
		mnl_attr_put_u32(reply, RTA_OIF, cps_conf->back_kni_index);
		rm->rtm_protocol = RTPROT_STATIC;
		rm->rtm_type = RTN_UNICAST;
		*gw_addr = NULL;
		break;
	case GK_DROP:
		put_priority(reply, fib->u.gateway.props.priority);
		rm->rtm_protocol = fib->u.drop.props.rt_proto;
		rm->rtm_type = RTN_BLACKHOLE;
		*gw_addr = NULL;
		break;
	default:
		rte_panic("Invalid FIB action (%u) in FIB while being processed by CPS block in %s\n",
			fib->action, __func__);
		return;
	}
}

static int
rd_send_batch(struct cps_config *cps_conf, struct mnl_nlmsg_batch *batch,
	const char *daemon, uint32_t seq, uint32_t pid, int done)
{
	/* Address of routing daemon. */
	struct sockaddr_nl rd_sa;
	int ret = 0;

	if (done) {
		struct nlmsghdr *done =
			mnl_nlmsg_put_header(mnl_nlmsg_batch_current(batch));
		done->nlmsg_type = NLMSG_DONE;
		done->nlmsg_flags = NLM_F_MULTI;
		done->nlmsg_seq = seq;
		done->nlmsg_pid = cps_conf->nl_pid;
		if (!mnl_nlmsg_batch_next(batch)) {
			/* Send the *full* batch without the DONE message. */
			ret = rd_send_batch(cps_conf, batch,
				daemon, seq, pid, false);
			if (ret < 0)
				return ret;
			/* Go on to send the DONE message. */
		}
	}

	memset(&rd_sa, 0, sizeof(rd_sa));
	rd_sa.nl_family = AF_NETLINK;
	rd_sa.nl_pid = pid;

	if (sendto_with_yield(mnl_socket_get_fd(cps_conf->rd_nl),
			mnl_nlmsg_batch_head(batch),
			mnl_nlmsg_batch_size(batch),
			(struct sockaddr *)&rd_sa, sizeof(rd_sa),
			cps_conf) < 0) {
		ret = -errno;
		G_LOG(ERR,
			"sendto_with_yield: cannot dump route batch to %s daemon (pid=%u seq=%u): %s\n",
			daemon, pid, seq, strerror(errno));
	}

	mnl_nlmsg_batch_reset(batch);
	return ret;
}

static void
spinlock_lock_with_yield(rte_spinlock_t *sl, struct cps_config *cps_conf)
{
	int ret;
	while ((ret = rte_spinlock_trylock_tm(sl)) == 0)
		rd_yield(cps_conf);
	RTE_VERIFY(ret == 1);
}

static int
rd_getroute_ipv4(struct cps_config *cps_conf, struct gk_lpm *ltbl,
	struct mnl_nlmsg_batch *batch, const struct nlmsghdr *req)
{
	struct rte_lpm_iterator_state state;
	const struct rte_lpm_rule *re4;
	int index, ret;

	spinlock_lock_with_yield(&ltbl->lock, cps_conf);
	ret = rte_lpm_iterator_state_init(ltbl->lpm, 0, 0, &state);
	if (ret < 0) {
		rte_spinlock_unlock_tm(&ltbl->lock);
		G_LOG(ERR, "Failed to initialize the IPv4 LPM rule iterator state in %s\n",
			__func__);
		return ret;
	}

	index = rte_lpm_rule_iterate(&state, &re4);
	while (index >= 0) {
		struct gk_fib *fib = &ltbl->fib_tbl[re4->next_hop];
		struct ipaddr *gw_addr;
		struct nlmsghdr *reply =
			mnl_nlmsg_put_header(mnl_nlmsg_batch_current(batch));

		rd_fill_getroute_reply(cps_conf, reply, fib,
			AF_INET, req->nlmsg_seq, state.depth, &gw_addr);

		/* Add address. */
		mnl_attr_put_u32(reply, RTA_DST, htonl(re4->ip));

		if (fib->action == GK_FWD_GRANTOR) {
			unsigned int i;
			for (i = 0; i < fib->u.grantor.set->num_entries; i++) {
				gw_addr = &fib->u.grantor.set->entries[i]
					.eth_cache->ip_addr;
				mnl_attr_put_u32(reply, RTA_GATEWAY,
					gw_addr->ip.v4.s_addr);
			}
		} else if (gw_addr != NULL) {
			/* Only report gateway for main routes. */
			mnl_attr_put_u32(reply, RTA_GATEWAY,
				gw_addr->ip.v4.s_addr);
		}

		if (!mnl_nlmsg_batch_next(batch)) {
			/*
			 * Do not access @fib or any FIB-related variable
			 * without the lock.
			 */
			rte_spinlock_unlock_tm(&ltbl->lock);
			ret = rd_send_batch(cps_conf, batch, "IPv4",
				req->nlmsg_seq, req->nlmsg_pid, false);
			if (ret < 0)
				return ret;
			/*
			 * Obtain the lock when starting a new Netlink batch.
			 * For the last batch that won't be sent in this function,
			 * the lock will be released at the end.
			 */
			spinlock_lock_with_yield(&ltbl->lock, cps_conf);
		}

		index = rte_lpm_rule_iterate(&state, &re4);
	}

	rte_spinlock_unlock_tm(&ltbl->lock);
	return 0;
}

static int
rd_getroute_ipv6(struct cps_config *cps_conf, struct gk_lpm *ltbl,
	struct mnl_nlmsg_batch *batch, const struct nlmsghdr *req)
{
	struct rte_lpm6_iterator_state state6;
	struct rte_lpm6_rule re6;
	int index, ret;

	spinlock_lock_with_yield(&ltbl->lock, cps_conf);
	ret = rte_lpm6_iterator_state_init(ltbl->lpm6, 0, 0, &state6);
	if (ret < 0) {
		rte_spinlock_unlock_tm(&ltbl->lock);
		G_LOG(ERR, "Failed to initialize the IPv6 LPM rule iterator state in %s\n",
			__func__);
		return ret;
	}

	index = rte_lpm6_rule_iterate(&state6, &re6);
	while (index >= 0) {
		struct gk_fib *fib = &ltbl->fib_tbl6[re6.next_hop];
		struct ipaddr *gw_addr;
		struct nlmsghdr *reply =
			mnl_nlmsg_put_header(mnl_nlmsg_batch_current(batch));

		rd_fill_getroute_reply(cps_conf, reply, fib,
			AF_INET6, req->nlmsg_seq, re6.depth, &gw_addr);

		/* Add address. */
		mnl_attr_put(reply, RTA_DST,
			sizeof(struct in6_addr), re6.ip);

		if (fib->action == GK_FWD_GRANTOR) {
			unsigned int i;
			for (i = 0; i < fib->u.grantor.set->num_entries; i++) {
				gw_addr = &fib->u.grantor.set->entries[i]
					.eth_cache->ip_addr;
				mnl_attr_put(reply, RTA_GATEWAY,
					sizeof(struct in6_addr),
					&gw_addr->ip.v6);
			}
		} else if (gw_addr != NULL) {
			/* Only report gateway for main routes. */
			mnl_attr_put(reply, RTA_GATEWAY,
				sizeof(struct in6_addr), &gw_addr->ip.v6);
		}

		if (!mnl_nlmsg_batch_next(batch)) {
			/*
			 * Do not access @fib or any FIB-related variable
			 * without the lock.
			 */
			rte_spinlock_unlock_tm(&ltbl->lock);
			ret = rd_send_batch(cps_conf, batch, "IPv6",
				req->nlmsg_seq, req->nlmsg_pid, false);
			if (ret < 0)
				return ret;
			/*
			 * Obtain the lock when starting a new Netlink batch.
			 * For the last batch that won't be sent in this function,
			 * the lock will be released at the end.
			 */
			spinlock_lock_with_yield(&ltbl->lock, cps_conf);
		}

		index = rte_lpm6_rule_iterate(&state6, &re6);
	}

	rte_spinlock_unlock_tm(&ltbl->lock);
	return 0;
}

static int
rd_getroute(const struct nlmsghdr *req, struct cps_config *cps_conf, int *err)
{
	/*
	 * Buffer length set according to libmnl documentation:
	 * the buffer that you have to use to store the batch must be
	 * double of MNL_SOCKET_BUFFER_SIZE to ensure that the last
	 * message (message N+1) that did not fit into the batch is
	 * written inside valid memory boundaries.
	 */
	char buf[2 * MNL_SOCKET_BUFFER_SIZE];
	struct mnl_nlmsg_batch *batch;
	struct gk_lpm *ltbl = &cps_conf->gk->lpm_tbl;
	const char *family_str;
	int family;

	if (mnl_nlmsg_get_payload_len(req) < sizeof(struct rtgenmsg)) {
		G_LOG(ERR, "Not enough room in CPS GETROUTE message from routing daemon in %s\n",
			__func__);
		*err = -EINVAL;
		goto out;
	}

	family = ((struct rtgenmsg *)mnl_nlmsg_get_payload(req))->rtgen_family;

	switch (family) {
	case AF_INET:
		family_str = "IPv4";
		break;
	case AF_INET6:
		family_str = "IPv6";
		break;
	case AF_UNSPEC:
		family_str = "IPV4/IPv6";
		break;
	case AF_MPLS:
		family_str = "MPLS";
		break;
	default:
		G_LOG(ERR, "Unsupported address family type (%d) in %s\n",
			family, __func__);
		*err = -EAFNOSUPPORT;
		goto out;
	}

	batch = mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);
	if (batch == NULL) {
		G_LOG(ERR, "Failed to allocate a batch for a GETROUTE reply\n");
		*err = -ENOMEM;
		goto out;
	}

	if (family == AF_INET || family == AF_UNSPEC) {
		if (!ipv4_configured(cps_conf->net)) {
			if (family == AF_UNSPEC)
				goto ipv6;
			else {
				*err = -EAFNOSUPPORT;
				goto free_batch;
			}
		}

		*err = rd_getroute_ipv4(cps_conf, ltbl, batch, req);
		if (*err < 0)
			goto free_batch;
	}
ipv6:
	if (family == AF_INET6 || family == AF_UNSPEC) {
		if (!ipv6_configured(cps_conf->net)) {
			if (family == AF_UNSPEC)
				goto send;
			else {
				*err = -EAFNOSUPPORT;
				goto free_batch;
			}
		}

		*err = rd_getroute_ipv6(cps_conf, ltbl, batch, req);
		if (*err < 0)
			goto free_batch;
	}
send:
	/* In the case of no entries, the only message sent is NLMSG_DONE. */
	*err = rd_send_batch(cps_conf, batch, family_str,
		req->nlmsg_seq, req->nlmsg_pid, true);

free_batch:
	mnl_nlmsg_batch_stop(batch);
out:
	return MNL_CB_OK;
}

static void
rd_fill_getlink_reply(const struct cps_config *cps_conf,
	struct mnl_nlmsg_batch *batch,
	const char *kni_name, unsigned int kni_index, unsigned int kni_mtu,
	uint32_t seq)
{
	struct nlmsghdr *reply;
	struct ifinfomsg *ifim;

	reply = mnl_nlmsg_put_header(mnl_nlmsg_batch_current(batch));
	reply->nlmsg_type = RTM_NEWLINK;
	reply->nlmsg_flags = NLM_F_MULTI;
	reply->nlmsg_seq = seq;
	reply->nlmsg_pid = cps_conf->nl_pid;

	ifim = mnl_nlmsg_put_extra_header(reply, sizeof(*ifim));
	ifim->ifi_family = AF_UNSPEC;
	ifim->ifi_type = ARPHRD_ETHER;
	ifim->ifi_index = kni_index;
	ifim->ifi_flags = IFF_UP|IFF_LOWER_UP;
	ifim->ifi_change = 0xFFFFFFFF;

	mnl_attr_put_strz(reply, IFLA_IFNAME, kni_name);
	mnl_attr_put_u32(reply, IFLA_MTU, kni_mtu);
}

static int
rd_getlink(const struct nlmsghdr *req, struct cps_config *cps_conf, int *err)
{
	char buf[2 * MNL_SOCKET_BUFFER_SIZE];
	struct mnl_nlmsg_batch *batch;

	batch = mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);
	if (batch == NULL) {
		G_LOG(ERR, "Failed to allocate a batch for a GETLINK reply\n");
		*err = -ENOMEM;
		goto out;
	}

	rd_fill_getlink_reply(cps_conf, batch,
		rte_kni_get_name(cps_conf->front_kni),
		cps_conf->front_kni_index, cps_conf->net->front.mtu,
		req->nlmsg_seq);
	if (!mnl_nlmsg_batch_next(batch)) {
		/* Send whatever was in the batch, if anything. */
		*err = rd_send_batch(cps_conf, batch, "LINK",
			req->nlmsg_seq, req->nlmsg_pid, false);
		if (*err < 0)
			goto free_batch;
	}

	if (cps_conf->net->back_iface_enabled) {
		rd_fill_getlink_reply(cps_conf, batch,
			rte_kni_get_name(cps_conf->back_kni),
			cps_conf->back_kni_index,
			cps_conf->net->back.mtu, req->nlmsg_seq);
		if (!mnl_nlmsg_batch_next(batch)) {
			*err = rd_send_batch(cps_conf, batch, "LINK",
				req->nlmsg_seq, req->nlmsg_pid, false);
			if (*err < 0)
				goto free_batch;
		}
	}

	*err = rd_send_batch(cps_conf, batch, "LINK",
		req->nlmsg_seq, req->nlmsg_pid, true);

free_batch:
	mnl_nlmsg_batch_stop(batch);
out:
	return MNL_CB_OK;
}

static int
rd_modroute(const struct nlmsghdr *req, const struct cps_config *cps_conf,
	int *err)
{
	struct nlattr *tb[__RTA_MAX] = {};
	struct rtmsg *rm = mnl_nlmsg_get_payload(req);
	struct route_update update;

	if (unlikely(cps_conf->gk == NULL)) {
		/*
		 * Grantor only runs CPS for ECMP support and
		 * shouldn't be receiving route updates.
		 */
		G_LOG(WARNING,
			"The system is running as Grantor, and there shouldn't be any rtnetlink message processed under this configuration while receiving route update messages\n");
		*err = -EOPNOTSUPP;
		goto out;
	}

	G_LOG(DEBUG, "cps update: [%s] family=%u dst_len=%u src_len=%u tos=%u table=%u protocol=%u scope=%u type=%u flags=%x\n",
		req->nlmsg_type == RTM_NEWROUTE ? "NEW" : "DEL",
		rm->rtm_family, rm->rtm_dst_len, rm->rtm_src_len,
		rm->rtm_tos, rm->rtm_table, rm->rtm_protocol,
		rm->rtm_scope, rm->rtm_type, rm->rtm_flags);

	memset(&update, 0, sizeof(update));
	update.valid = false;
	update.type = req->nlmsg_type;
	update.family = rm->rtm_family;

	/* Destination prefix length, e.g., 24 or 32 for IPv4. */
	update.prefix_info.len = rm->rtm_dst_len;

	/* Default to an invalid index number. */
	update.oif_index = 0;

	/* Route type. */
	update.rt_type = rm->rtm_type;

	/* Route origin (routing daemon). */
	update.rt_props.rt_proto = rm->rtm_protocol;
	/* Default route priority. */
	update.rt_props.priority = 0;

	/*
	 * Flags over the update request.
	 * Example: NLM_F_REQUEST|NLM_F_ACK|NLM_F_REPLACE|NLM_F_CREATE
	 */
	update.rt_flags = req->nlmsg_flags;

	switch (rm->rtm_family) {
	case AF_INET:
		if (!ipv4_configured(cps_conf->net)) {
			*err = -EAFNOSUPPORT;
			goto out;
		}
		mnl_attr_parse(req, sizeof(*rm), data_ipv4_attr_cb, tb);
		*err = attr_get(&update, rm->rtm_family, tb);
		if (*err)
			goto out;
		break;
	case AF_INET6:
		if (!ipv6_configured(cps_conf->net)) {
			*err = -EAFNOSUPPORT;
			goto out;
		}
		mnl_attr_parse(req, sizeof(*rm), data_ipv6_attr_cb, tb);
		*err = attr_get(&update, rm->rtm_family, tb);
		if (*err)
			goto out;
		break;
	default:
		G_LOG(NOTICE, "Unrecognized family in netlink event: %u\n",
			rm->rtm_family);
		*err = -EAFNOSUPPORT;
		goto out;
	}

	if (update.valid) {
		if (update.type == RTM_NEWROUTE) {
			*err = new_route(&update, cps_conf);
		} else if (likely(update.type == RTM_DELROUTE)) {
			*err = del_route(&update, cps_conf);
		} else {
			G_LOG(WARNING, "Receiving an unexpected update rule with type = %d\n",
				update.type);
			*err = -EOPNOTSUPP;
		}
	} else
		*err = -EINVAL;

out:
	return MNL_CB_OK;
}

static void
rd_fill_getaddr_reply(const struct cps_config *cps_conf,
	struct mnl_nlmsg_batch *batch, struct gatekeeper_if *iface,
	uint8_t family, unsigned int kni_index, uint32_t seq)
{
	struct nlmsghdr *reply;
	struct ifaddrmsg *ifam;

	reply = mnl_nlmsg_put_header(mnl_nlmsg_batch_current(batch));
	reply->nlmsg_type = RTM_NEWADDR;
	reply->nlmsg_flags = NLM_F_MULTI;
	reply->nlmsg_seq = seq;
	reply->nlmsg_pid = cps_conf->nl_pid;

	ifam = mnl_nlmsg_put_extra_header(reply, sizeof(*ifam));
	ifam->ifa_family = family;
	ifam->ifa_flags = IFA_F_PERMANENT;
	ifam->ifa_scope = RT_SCOPE_UNIVERSE;
	ifam->ifa_index = kni_index;

	/*
	 * The exact meaning of IFA_LOCAL and IFA_ADDRESS depend
	 * on the address family being used and the device type.
	 * For broadcast devices (like the interfaces we use),
	 * for IPv4 we specify both and they are used interchangeably.
	 * For IPv6, only IFA_ADDRESS needs to be set.
	 */

	if (family == AF_INET) {
		mnl_attr_put_u32(reply, IFA_LOCAL, iface->ip4_addr.s_addr);
		mnl_attr_put_u32(reply, IFA_ADDRESS, iface->ip4_addr.s_addr);
		ifam->ifa_prefixlen = iface->ip4_addr_plen;
	} else if (likely(family == AF_INET6)) {
		mnl_attr_put(reply, IFA_ADDRESS,
			sizeof(iface->ip6_addr), &iface->ip6_addr);
		ifam->ifa_prefixlen = iface->ip6_addr_plen;
	} else {
		rte_panic("Invalid address family (%hhu) in request while being processed by CPS block in %s\n",
			family, __func__);
	}
}

static int
rd_getaddr_iface(struct cps_config *cps_conf,
	struct mnl_nlmsg_batch *batch, struct gatekeeper_if *iface,
	uint8_t family, unsigned int kni_index, uint32_t seq, uint32_t pid)
{
	int ret = 0;

	if ((family == AF_INET || family == AF_UNSPEC)
			&& ipv4_if_configured(iface)) {
		rd_fill_getaddr_reply(cps_conf, batch, iface,
			AF_INET, kni_index, seq);
		if (!mnl_nlmsg_batch_next(batch)) {
			/* Send whatever was in the batch, if anything. */
			ret = rd_send_batch(cps_conf, batch, "IPv4",
				seq, pid, false);
			if (ret < 0)
				return ret;
		}
	}

	if ((family == AF_INET6 || family == AF_UNSPEC)
			&& ipv6_if_configured(iface)) {
		rd_fill_getaddr_reply(cps_conf, batch, iface,
			AF_INET6, kni_index, seq);
		if (!mnl_nlmsg_batch_next(batch)) {
			/* Send whatever was in the batch, if anything. */
			ret = rd_send_batch(cps_conf, batch, "IPv6",
				seq, pid, false);
			if (ret < 0)
				return ret;
		}
	}

	return ret;
}

static int
rd_getaddr(const struct nlmsghdr *req, struct cps_config *cps_conf, int *err)
{
	char buf[2 * MNL_SOCKET_BUFFER_SIZE];
	struct mnl_nlmsg_batch *batch;
	struct net_config *net_conf = cps_conf->net;
	int family;
	const char *family_str;

	if (mnl_nlmsg_get_payload_len(req) < sizeof(struct rtgenmsg)) {
		G_LOG(ERR, "Not enough room in CPS GETADDR message from routing daemon in %s\n",
			__func__);
		*err = -EINVAL;
		goto out;
	}

	family = ((struct rtgenmsg *)mnl_nlmsg_get_payload(req))->rtgen_family;

	switch (family) {
	case AF_INET:
		family_str = "IPv4";
		break;
	case AF_INET6:
		family_str = "IPv6";
		break;
	case AF_UNSPEC:
		family_str = "IPV4/IPv6";
		break;
	default:
		G_LOG(ERR, "Unsupported address family type (%d) in %s\n",
			family, __func__);
		*err = -EAFNOSUPPORT;
		goto out;
	}

	batch = mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);
	if (batch == NULL) {
		G_LOG(ERR, "Failed to allocate a batch for a GETADDR reply\n");
		*err = -ENOMEM;
		goto out;
	}

	*err = rd_getaddr_iface(cps_conf, batch, &net_conf->front, family,
		cps_conf->front_kni_index, req->nlmsg_seq, req->nlmsg_pid);
	if (*err < 0)
		goto free_batch;

	if (net_conf->back_iface_enabled) {
		*err = rd_getaddr_iface(cps_conf, batch, &net_conf->back,
			family, cps_conf->back_kni_index,
			req->nlmsg_seq, req->nlmsg_pid);
		if (*err < 0)
			goto free_batch;
	}

	*err = rd_send_batch(cps_conf, batch, family_str,
		req->nlmsg_seq, req->nlmsg_pid, true);

free_batch:
	mnl_nlmsg_batch_stop(batch);
out:
	return MNL_CB_OK;
}

static int
rd_cb(const struct nlmsghdr *req, void *arg)
{
	struct cps_config *cps_conf = arg;
	int ret = MNL_CB_OK;
	int err;

	/* Only requests should be received here. */
	if (!(req->nlmsg_flags & NLM_F_REQUEST)) {
		err = -EINVAL;
		goto out;
	}

	switch (req->nlmsg_type) {
	case RTM_NEWROUTE:
		/* FALLTHROUGH */
	case RTM_DELROUTE:
		ret = rd_modroute(req, cps_conf, &err);
		break;
	case RTM_GETROUTE:
		ret = rd_getroute(req, cps_conf, &err);
		break;
	case RTM_GETLINK:
		ret = rd_getlink(req, cps_conf, &err);
		break;
	case RTM_GETADDR:
		ret = rd_getaddr(req, cps_conf, &err);
		break;
	default:
		G_LOG(NOTICE, "Unrecognized netlink message type: %u\n",
			req->nlmsg_type);
		err = -EOPNOTSUPP;
		break;
	}
out:
	if ((req->nlmsg_flags & NLM_F_ACK) || err)
		rd_send_err(req, cps_conf, err);
	return ret;
}

/*
 * Receive a netlink message with the ability to pass flags to recvmsg().
 * This function is an adaptation of mnl_socket_recvfrom() from
 * http://git.netfilter.org/libmnl/tree/src/socket.c#n263, which does
 * not allow flags.
 */
static ssize_t
mnl_socket_recvfrom_flags(const struct mnl_socket *nl, void *buf, size_t bufsiz,
	int flags)
{
	ssize_t ret;
	struct sockaddr_nl addr;
	struct iovec iov = {
		.iov_base = buf,
		.iov_len  = bufsiz,
	};
	struct msghdr msg = {
		.msg_name       = &addr,
		.msg_namelen    = sizeof(struct sockaddr_nl),
		.msg_iov        = &iov,
		.msg_iovlen     = 1,
		.msg_control    = NULL,
		.msg_controllen = 0,
		.msg_flags      = 0,
	};
	ret = recvmsg(mnl_socket_get_fd(nl), &msg, flags);
	if (ret == -1)
		return ret;

	if (msg.msg_flags & MSG_TRUNC) {
		errno = ENOSPC;
		return -1;
	}
	if (msg.msg_namelen != sizeof(struct sockaddr_nl)) {
		errno = EINVAL;
		return -1;
	}
	return ret;
}

void
rd_process_events(struct cps_config *cps_conf)
{
	coro_transfer(&cps_conf->coro_root, &cps_conf->coro_rd);
}

static void
__rd_process_events(struct cps_config *cps_conf)
{
	unsigned int update_pkts = cps_conf->max_rt_update_pkts;
	do {
		char buf[MNL_SOCKET_BUFFER_SIZE];
		int ret = mnl_socket_recvfrom_flags(cps_conf->rd_nl, buf,
			sizeof(buf), MSG_DONTWAIT);
		if (ret == -1) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				G_LOG(ERR, "%s: recv: %s\n",
					__func__, strerror(errno));
			break;
		}

		ret = mnl_cb_run(buf, ret, 0, 0, rd_cb, cps_conf);
		if (ret != MNL_CB_OK)
			break;

		update_pkts--;
	} while (update_pkts > 0);
}

static void
cps_co_rd_main(void *arg)
{
	struct cps_config *cps_conf = arg;

	while (true) {
		__rd_process_events(cps_conf);
		rd_yield(cps_conf);
	}

	rte_panic("%s() terminated\n", __func__);
}

int
rd_alloc_coro(struct cps_config *cps_conf)
{
	const unsigned int stack_size_byte = 1024 * 1024; /* 1MB */
	const unsigned int stack_size_ptr = stack_size_byte / sizeof(void *);

	if (unlikely(coro_stack_alloc(&cps_conf->coro_rd_stack, stack_size_ptr)
			!= 1)) {
		G_LOG(ERR, "Failed to allocate stack for RD coroutine\n");
		return -1;
	}

	coro_create(&cps_conf->coro_root, NULL, NULL, NULL, 0);
	coro_create(&cps_conf->coro_rd, cps_co_rd_main, cps_conf,
		cps_conf->coro_rd_stack.sptr, cps_conf->coro_rd_stack.ssze);
	return 0;
}

void
rd_free_coro(struct cps_config *cps_conf)
{
	coro_destroy(&cps_conf->coro_rd);
	coro_destroy(&cps_conf->coro_root);
	coro_stack_free(&cps_conf->coro_rd_stack);
}
