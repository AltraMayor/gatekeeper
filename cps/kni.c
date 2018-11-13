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
#include <fcntl.h>
#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_malloc.h>

#include "gatekeeper_cps.h"
#include "gatekeeper_lls.h"
#include "gatekeeper_main.h"
#include "kni.h"

/* Number of times to attempt bring a KNI interface up or down. */
#define NUM_ATTEMPTS_KNI_LINK_SET (5)

/* Maximum number of updates for LPM table to serve at once. */
#define MAX_CPS_ROUTE_UPDATES (8)

/*
 * According to init_module(2) and delete_module(2), there
 * are no declarations for these functions in header files.
 */
extern long init_module(void *, unsigned long, const char *);
extern long delete_module(const char *, unsigned int);

int
kni_change_if(uint16_t port_id, uint8_t if_up)
{
	int ret = 0;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, GATEKEEPER, "cps: %s: invalid port ID %hu\n",
			__func__, port_id);
		return -EINVAL;
	}

	if (if_up != 0) {
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
		if (ret < 0)
			RTE_LOG(ERR, GATEKEEPER,
				"cps: %s: Failed to start port %hu\n",
				__func__, port_id);
	} else
		rte_eth_dev_stop(port_id);

	return ret;
}

int
kni_change_mtu(uint16_t port_id, unsigned int new_mtu)
{
	if (unlikely((new_mtu < ETHER_MIN_MTU) ||
			(new_mtu > ETHER_MAX_JUMBO_FRAME_LEN -
				(ETHER_HDR_LEN + ETHER_CRC_LEN))))
		return -EINVAL;

	return rte_eth_dev_set_mtu(port_id, new_mtu);
}

int
kni_disable_change_mac_address(__attribute__((unused)) uint16_t port_id,
	__attribute__((unused)) uint8_t *mac_addr)
{
	/*
	 * Gatekeeper does not support changing the MAC addresses
	 * of its NICs. For example, some blocks cache Ethernet
	 * headers and are not prepared to change the source MAC
	 * address in those cached headers.
	 *
	 * Therefore, we need to prevent any changes to the KNI's
	 * MAC address because it must always match the MAC address
	 * of its corresponding Gatekeeper interface.
	 */
	return -ENOTSUP;
}

static int
modify_ipaddr(struct mnl_socket *nl, unsigned int cmd, int flags,
	int family, void *ipaddr, uint8_t prefixlen, const char *kni_name)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	unsigned int seq;
	unsigned int portid = mnl_socket_get_portid(nl);
	int ret;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = cmd;
	nlh->nlmsg_flags = flags|NLM_F_ACK;
	nlh->nlmsg_seq = seq = time(NULL);

	ifa = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifa));
	ifa->ifa_family = family;
	ifa->ifa_prefixlen = prefixlen;
	ifa->ifa_scope = RT_SCOPE_UNIVERSE;
	if ((ifa->ifa_index = if_nametoindex(kni_name)) == 0) {
		RTE_LOG(ERR, GATEKEEPER, "cps: %s cannot find device %s\n",
			__func__, kni_name);
		return -1;
	}

	if (ifa->ifa_family == AF_INET)
		mnl_attr_put_u32(nlh, IFA_LOCAL, *(uint32_t *)ipaddr);
	else if (ifa->ifa_family == AF_INET6)
		mnl_attr_put(nlh, IFA_LOCAL, 16, ipaddr);
	else
		rte_panic("%s: address family (%d) not recognized\n",
			__func__, family);

	ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER, "cps: mnl_socket_sendto: cannot update %s with new IP address (family %d) (operation %d): %s\n",
			kni_name, family, cmd, strerror(errno));
		return ret;
	}

	/*
	 * We specified NLM_F_ACK to get an acknowledgement, so receive the
	 * ACK and verify that the interface configuration message was valid
	 * using the default libmnl callback for doing message verification.
	 */

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (ret == -1) {
		RTE_LOG(ERR, GATEKEEPER, "cps: mnl_socket_recvfrom: cannot update %s with new IP address (family %d) (operation %d): %s\n",
			kni_name, family, cmd, strerror(errno));
		return ret;
	}

	ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
	if (ret == -1) {
		RTE_LOG(ERR, GATEKEEPER, "cps: mnl_cb_run: cannot update %s with new IP address (family %d) (operation %d): %s\n",
			kni_name, family, cmd, strerror(errno));
		return ret;
	}

	return ret;
}

static int
add_ipaddr(struct mnl_socket *nl, int family, void *ipaddr,
	uint8_t prefixlen, const char *kni_name)
{
	return modify_ipaddr(nl, RTM_NEWADDR,
		NLM_F_CREATE|NLM_F_REQUEST|NLM_F_EXCL, family,
		ipaddr, prefixlen, kni_name);
}

static int
modify_link(struct mnl_socket *nl, struct rte_kni *kni,
	const char *kni_name, int if_up)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm;
	unsigned int seq, flags = 0;
	int pid;

	if (if_up)
		flags |= IFF_UP;
	else
		flags &= ~IFF_UP;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	nlh->nlmsg_seq = seq = time(NULL);

	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
	ifm->ifi_family = AF_UNSPEC;
	ifm->ifi_change = IFF_UP;
	ifm->ifi_flags = flags;

	mnl_attr_put_str(nlh, IFLA_IFNAME, kni_name);

	/*
	 * The KNI library registers callbacks for MTU changes and
	 * interface up/down events through ethtool. When these
	 * operations are requested to the kernel through netlink
	 * messages, they go back to DPDK in userspace when
	 * rte_kni_handle_request() is invoked. Therefore, if we
	 * issue this request, we need another process to call
	 * rte_kni_handle_request() to allow it to proceed.
	 *
	 * The DPDK documentation suggests using ifconfig from a
	 * shell to bring a KNI up after the application starts and
	 * calls rte_kni_handle_request(). To do so automatically,
	 * we have to fork a child process to issue the request
	 * while the parent calls rte_kni_handle_request().
	 */

	pid = fork();
	if (pid == -1) {
		RTE_LOG(ERR, GATEKEEPER,
			"cps: fork failed, can't modify KNI %s link: %s\n",
			kni_name, strerror(errno));
		return -1;
	} else if (pid == 0) {
		/*
		 * Send request to kernel, which will be sent back
		 * to userspace for the parent to handle.
		 */
		int ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER,
				"cps: mnl_socket_sendto: cannot bring KNI %s %s: %s\n",
				kni_name, if_up ? "up" : "down",
				strerror(errno));
			_exit(EXIT_FAILURE);
		}
		_exit(EXIT_SUCCESS);
	} else {
		unsigned int attempts = 0;
		unsigned int portid = mnl_socket_get_portid(nl);
		do {
			int status;

			/* Try to process child's request. */
			int ret = rte_kni_handle_request(kni);
			if (ret < 0) {
				RTE_LOG(ERR, KNI, "%s: error in handling userspace request\n",
					__func__);
				goto next;
			}

			/* Check if child has finished submitting request. */
			ret = waitpid(pid, &status, WNOHANG);
			if (ret == 0) {
				/* Keep trying to handle the KNI request. */
				goto next;
			} else if (ret == -1) {
				RTE_LOG(ERR, GATEKEEPER, "cps: waitpid: %s\n",
					strerror(errno));
				goto kill;
			}

			ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
			if (ret == -1) {
				RTE_LOG(ERR, GATEKEEPER, "cps: mnl_socket_recvfrom: cannot bring KNI %s %s: %s\n",
					kni_name, if_up ? "up" : "down",
					strerror(errno));
				return ret;
			}

			ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
			if (ret == -1) {
				RTE_LOG(ERR, GATEKEEPER, "cps: mnl_cb_run: cannot bring KNI %s %s: %s\n",
					kni_name, if_up ? "up" : "down",
					strerror(errno));
				return ret;
			}

			return 0;
next:
			attempts++;
			sleep(1);
		} while (attempts < NUM_ATTEMPTS_KNI_LINK_SET);
	}
kill:
	/* Failed to wait for child or waited for too many attempts. */
	kill(pid, SIGTERM);
	return -1;
}

int
kni_config_ip_addrs(struct rte_kni *kni, struct gatekeeper_if *iface)
{
	struct mnl_socket *nl;
	const char *kni_name = rte_kni_get_name(kni);
	int ret = 0;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		RTE_LOG(ERR, GATEKEEPER, "cps: mnl_socket_open: %s\n",
			strerror(errno));
		return -1;
	}

	ret = mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER, "cps: mnl_socket_bind: %s\n",
			strerror(errno));
		goto close;
	}

	/* Add global and link-local IP addresses. */
	if (ipv4_if_configured(iface)) {
		ret = add_ipaddr(nl, AF_INET, &iface->ip4_addr,
			iface->ip4_addr_plen, kni_name);
		if (ret < 0)
			goto close;
	}

	if (ipv6_if_configured(iface)) {
		ret = add_ipaddr(nl, AF_INET6, &iface->ip6_addr,
			iface->ip6_addr_plen, kni_name);
		if (ret < 0)
			goto close;
	}

close:
	mnl_socket_close(nl);
	return ret;
}

int
kni_config_link(struct rte_kni *kni)
{
	struct mnl_socket *nl;
	const char *kni_name = rte_kni_get_name(kni);
	int ret = 0;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		RTE_LOG(ERR, GATEKEEPER, "cps: mnl_socket_open: %s\n",
			strerror(errno));
		return -1;
	}

	ret = mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER, "cps: mnl_socket_bind: %s\n",
			strerror(errno));
		goto close;
	}

	/* Bring interface up. */
	ret = modify_link(nl, kni, kni_name, true);

close:
	mnl_socket_close(nl);
	return ret;
}

void
route_event_sock_close(struct cps_config *cps_conf)
{
	if (cps_conf->nl != NULL) {
		mnl_socket_close(cps_conf->nl);
		cps_conf->nl = NULL;
	}
}

int
route_event_sock_open(struct cps_config *cps_conf)
{
	struct mnl_socket *nl;
	int ret;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		RTE_LOG(ERR, GATEKEEPER, "cps: %s: mnl_socket_open: %s\n",
			__func__, strerror(errno));
		return -1;
	}
	cps_conf->nl = nl;

	/*
	 * TODO This bind will get all changes that arrive at the kernel,
	 * but it will duplicate the FIB: one in the kernel and another
	 * in Gatekeeper.
	 */
	ret = mnl_socket_bind(nl, RTMGRP_IPV4_ROUTE|RTMGRP_IPV6_ROUTE,
		MNL_SOCKET_AUTOPID);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER, "cps: %s: mnl_socket_bind: %s\n",
			__func__, strerror(errno));
		goto close;
	}

	return 0;

close:
	route_event_sock_close(cps_conf);
	return ret;
}

static inline void
inet_print(const char *msg, struct in_addr *in)
{
	char buf[INET_ADDRSTRLEN];
	RTE_LOG(INFO, GATEKEEPER, "cps update: %s: %s\n", msg,
		inet_ntop(AF_INET, &in->s_addr, buf, sizeof(buf)));
}

static inline void
inet6_print(const char *msg, struct in6_addr *in6)
{
	char buf[INET6_ADDRSTRLEN];
	RTE_LOG(INFO, GATEKEEPER, "cps update: %s: %s\n", msg,
		inet_ntop(AF_INET6, &in6->s6_addr, buf, sizeof(buf)));
}

static void
attr_get(struct cps_config *cps_conf,
	struct route_update *update, int family, struct nlattr *tb[])
{
	bool dst_present = false;
	bool gw_present = false;

	if (tb[RTA_MULTIPATH]) {
		/*
		 * XXX This is the attribute used to implement ECMP.
		 * We should more closely parse this attribute and
		 * return the appropriate information through
		 * @update to Grantor, if we're running Grantor.
		 *
		 * Example usage:
		 *
		 * struct rtnexthop *rt =
		 *	mnl_attr_get_payload(tb[RTA_MULTIPATH]);
		 */
		if (cps_conf->debug)
			RTE_LOG(INFO, GATEKEEPER, "cps update: multipath\n");
	}
	if (tb[RTA_DST]) {
		if (family == AF_INET) {
			struct in_addr *addr =
				mnl_attr_get_payload(tb[RTA_DST]);
			rte_memcpy(&update->ip.v4,
				addr, sizeof(update->ip.v4));
			if (cps_conf->debug)
				inet_print("dst", addr);
		} else if (likely(family == AF_INET6)) {
			struct in6_addr *addr =
				mnl_attr_get_payload(tb[RTA_DST]);
			rte_memcpy(&update->ip.v6,
				addr, sizeof(update->ip.v6));
			if (cps_conf->debug)
				inet6_print("dst", addr);
		} else {
			RTE_LOG(WARNING, GATEKEEPER,
				"cps update: unknown address family %d at %s!\n",
				family, __func__);
			return;
		}

		dst_present = true;
	}
	if (tb[RTA_SRC]) {
		char buf[INET6_ADDRSTRLEN];

		if (family == AF_INET) {
			struct in_addr *addr =
				mnl_attr_get_payload(tb[RTA_SRC]);
			if (inet_ntop(AF_INET, &addr->s_addr, buf,
					sizeof(buf)) == NULL) {
				RTE_LOG(ERR, GATEKEEPER,
					"%s: failed to convert a number to an IPv4 address (%s)\n",
					__func__, strerror(errno));
				return;
			}
		} else if (likely(family == AF_INET6)) {
			struct in6_addr *addr =
				mnl_attr_get_payload(tb[RTA_SRC]);
			if (inet_ntop(AF_INET6, &addr->s6_addr, buf,
					sizeof(buf)) == NULL) {
				RTE_LOG(ERR, GATEKEEPER,
					"%s: failed to convert a number to an IPv6 address (%s)\n",
					__func__, strerror(errno));
				return;
			}
		} else {
			RTE_LOG(WARNING, GATEKEEPER,
				"cps update: unknown address family %d at %s!\n",
				family, __func__);
			return;
		}

		RTE_LOG(WARNING, GATEKEEPER,
			"cps update: the rtnetlink command has information (RTA_SRC with IP address %s) that we don't need or don't honor!\n",
			buf);
	}
	if (tb[RTA_OIF]) {
		update->oif_index = mnl_attr_get_u32(tb[RTA_OIF]);

		if (cps_conf->debug)
			RTE_LOG(INFO, GATEKEEPER, "cps update: oif=%u\n",
				update->oif_index);
	}
	if (tb[RTA_FLOW]) {
		RTE_LOG(WARNING, GATEKEEPER,
			"cps update: the rtnetlink command has information (RTA_FLOW with flow=%u) that we don't need or don't honor!\n",
			mnl_attr_get_u32(tb[RTA_FLOW]));
	}
	if (tb[RTA_PREFSRC]) {
		char buf[INET6_ADDRSTRLEN];

		if (family == AF_INET) {
			struct in_addr *addr =
				mnl_attr_get_payload(tb[RTA_PREFSRC]);
			if (inet_ntop(AF_INET, &addr->s_addr, buf,
					sizeof(buf)) == NULL) {
				RTE_LOG(ERR, GATEKEEPER,
					"%s: failed to convert a number to an IPv4 address (%s)\n",
					__func__, strerror(errno));
				return;
			}
		} else if (likely(family == AF_INET6)) {
			struct in6_addr *addr =
				mnl_attr_get_payload(tb[RTA_PREFSRC]);
			if (inet_ntop(AF_INET6, &addr->s6_addr, buf,
					sizeof(buf)) == NULL) {
				RTE_LOG(ERR, GATEKEEPER,
					"%s: failed to convert a number to an IPv6 address (%s)\n",
					__func__, strerror(errno));
				return;
			}
		} else {
			RTE_LOG(WARNING, GATEKEEPER,
				"cps update: unknown address family %d at %s!\n",
				family, __func__);
			return;
		}

		RTE_LOG(WARNING, GATEKEEPER,
			"cps update: the rtnetlink command has information (RTA_PREFSRC with IP address %s) that we don't need or don't honor!\n",
			buf);
	}
	if (tb[RTA_GATEWAY]) {
		if (family == AF_INET) {
			struct in_addr *addr =
				mnl_attr_get_payload(tb[RTA_GATEWAY]);
			rte_memcpy(&update->gw.v4,
				addr, sizeof(update->gw.v4));
			if (cps_conf->debug)
				inet_print("gw", addr);
		} else if (likely(family == AF_INET6)) {
			struct in6_addr *addr =
				mnl_attr_get_payload(tb[RTA_GATEWAY]);
			rte_memcpy(&update->gw.v6,
				addr, sizeof(update->gw.v6));
			if (cps_conf->debug)
				inet6_print("gw", addr);
		} else {
			RTE_LOG(WARNING, GATEKEEPER,
				"cps update: unknown address family %d at %s!\n",
				family, __func__);
			return;
		}

		gw_present = true;
	}
	if (tb[RTA_PRIORITY]) {
		RTE_LOG(WARNING, GATEKEEPER,
			"cps update: the rtnetlink command has information (RTA_PRIORITY with prio=%u) that we don't need or don't honor!\n",
			mnl_attr_get_u32(tb[RTA_PRIORITY]));
	}

	update->valid = dst_present &&
		(update->type == RTM_DELROUTE ||
		(update->type == RTM_NEWROUTE && gw_present));
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

static int
route_cb(const struct nlmsghdr *nlh, void *arg)
{
	struct nlattr *tb[__RTA_MAX] = {};
	struct cps_config *cps_conf = get_cps_conf();
	struct rtmsg *rm = mnl_nlmsg_get_payload(nlh);
	struct route_update *update = arg;

	update->valid = false;

	if (nlh->nlmsg_type != RTM_NEWROUTE &&
			nlh->nlmsg_type != RTM_DELROUTE) {
		RTE_LOG(NOTICE, GATEKEEPER,
			"cps: unrecognized netlink message type: %u\n",
			nlh->nlmsg_type);
		return MNL_CB_OK;
	}

	if (cps_conf->debug)
		RTE_LOG(INFO, GATEKEEPER, "cps update: [%s] family=%u dst_len=%u src_len=%u tos=%u table=%u protocol=%u scope=%u type=%u flags=%x\n",
			nlh->nlmsg_type == RTM_NEWROUTE ? "NEW" : "DEL",
			rm->rtm_family, rm->rtm_dst_len, rm->rtm_src_len,
			rm->rtm_tos, rm->rtm_table, rm->rtm_protocol,
			rm->rtm_protocol, rm->rtm_scope, rm->rtm_flags);

	update->type = nlh->nlmsg_type;
	update->family = rm->rtm_family;

	/* Destination prefix length, e.g., 24 or 32 for IPv4. */
	update->prefix_len = rm->rtm_dst_len;

	/* Default to an invalid index number. */
	update->oif_index = 0;

	switch(rm->rtm_family) {
	case AF_INET:
		mnl_attr_parse(nlh, sizeof(*rm), data_ipv4_attr_cb, tb);
		attr_get(cps_conf, update, rm->rtm_family, tb);
		break;
	case AF_INET6:
		mnl_attr_parse(nlh, sizeof(*rm), data_ipv6_attr_cb, tb);
		attr_get(cps_conf, update, rm->rtm_family, tb);
		break;
	default:
		RTE_LOG(NOTICE, GATEKEEPER,
			"cps: unrecognized family in netlink event: %u\n",
			rm->rtm_family);
		break;
	}

	return MNL_CB_OK;
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

static int
new_route(struct route_update *update, struct cps_config *cps_conf)
{
	int ret;
	uint16_t proto;
	char ip_buf[INET6_ADDRSTRLEN];
	char ipp_buf[INET6_ADDRSTRLEN + 4];
	int gw_fib_id;
	struct ip_prefix prefix_info;
	struct ipaddr gw_addr;
	struct gk_fib *gw_fib;
	struct gk_lpm *ltbl = &cps_conf->gk->lpm_tbl;

	if (update->family == AF_INET) {
		proto = ETHER_TYPE_IPv4;
		gw_fib_id = lpm_lookup_ipv4(ltbl->lpm, update->gw.v4.s_addr);
		if (gw_fib_id < 0)
			return -1;
		gw_fib = &ltbl->fib_tbl[gw_fib_id];

		if (inet_ntop(AF_INET, &update->ip.v4.s_addr,
				ip_buf, sizeof(ip_buf)) == NULL)
			return -1;

		ret = snprintf(ipp_buf, sizeof(ipp_buf), "%s/%hhu",
			ip_buf, update->prefix_len);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(ipp_buf));
	} else if (likely(update->family == AF_INET6)) {
		proto = ETHER_TYPE_IPv6;
		gw_fib_id = lpm_lookup_ipv6(ltbl->lpm6, update->gw.v6.s6_addr);
		if (gw_fib_id < 0)
			return -1;
		gw_fib = &ltbl->fib_tbl6[gw_fib_id];

		if (inet_ntop(AF_INET6, &update->ip.v6.s6_addr,
				ip_buf, sizeof(ip_buf)) == NULL)
			return -1;

		ret = snprintf(ipp_buf, sizeof(ipp_buf), "%s/%hhu",
			ip_buf, update->prefix_len);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(ipp_buf));
	} else {
		RTE_LOG(WARNING, GATEKEEPER,
			"cps update: unknown address family %d at %s!\n",
			update->family, __func__);
		return -1;
	}

	prefix_info.str = ipp_buf;
	prefix_info.addr.proto = proto;
	rte_memcpy(&prefix_info.addr.ip, &update->ip,
		sizeof(prefix_info.addr.ip));
	prefix_info.len = update->prefix_len;

	gw_addr.proto = proto;
	rte_memcpy(&gw_addr.ip, &update->gw, sizeof(gw_addr.ip));

	if (gw_fib->action == GK_FWD_NEIGHBOR_FRONT_NET) {
		if (update->oif_index != 0) {
			const char *kni_name =
				rte_kni_get_name(cps_conf->front_kni);
			if (update->oif_index != if_nametoindex(kni_name)) {
				RTE_LOG(WARNING, GATEKEEPER,
					"cps: the output KNI interface for prefix %s is not the front interface while the gateway for the prefix in Gatekeeper is a neighbor of the front network!\n",
					prefix_info.str);
				return -1;
			}
		}

		return add_fib_entry_numerical(&prefix_info, NULL, &gw_addr,
			GK_FWD_GATEWAY_FRONT_NET, cps_conf->gk);
	}

	if (gw_fib->action == GK_FWD_NEIGHBOR_BACK_NET) {
		if (update->oif_index != 0) {
			const char *kni_name =
				rte_kni_get_name(cps_conf->back_kni);
			if (update->oif_index != if_nametoindex(kni_name)) {
				RTE_LOG(WARNING, GATEKEEPER,
					"cps: the output KNI interface for prefix %s is not the back interface while the gateway for the prefix in Gatekeeper is a neighbor of the back network!\n",
					prefix_info.str);
				return -1;
			}
		}

		return add_fib_entry_numerical(&prefix_info, NULL, &gw_addr,
			GK_FWD_GATEWAY_BACK_NET, cps_conf->gk);
	}

	return -1;
}

static int
del_route(struct route_update *update, struct gk_config *gk_conf)
{
	int ret;
	char ip_buf[INET6_ADDRSTRLEN];
	char ipp_buf[INET6_ADDRSTRLEN + 4];
	struct ip_prefix prefix_info;

	if (update->family == AF_INET) {
		if (inet_ntop(AF_INET, &update->ip.v4.s_addr,
				ip_buf, sizeof(ip_buf)) == NULL)
			return -1;

		ret = snprintf(ipp_buf, sizeof(ipp_buf), "%s/%hhu",
			ip_buf, update->prefix_len);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(ipp_buf));

		prefix_info.addr.proto = ETHER_TYPE_IPv4;
		rte_memcpy(&prefix_info.addr.ip.v4, &update->ip.v4,
			sizeof(prefix_info.addr.ip.v4));
	} else if (likely(update->family == AF_INET6)) {
		if (inet_ntop(AF_INET6, &update->ip.v6.s6_addr,
				ip_buf, sizeof(ip_buf)) == NULL)
			return -1;

		ret = snprintf(ipp_buf, sizeof(ipp_buf), "%s/%hhu",
			ip_buf, update->prefix_len);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(ipp_buf));

		prefix_info.addr.proto = ETHER_TYPE_IPv6;
		rte_memcpy(&prefix_info.addr.ip.v6, &update->ip.v6,
			sizeof(prefix_info.addr.ip.v6));
	} else {
		RTE_LOG(WARNING, GATEKEEPER,
			"cps update: unknown address family %d at %s!\n",
			update->family, __func__);
		return -1;
	}

	prefix_info.str = ipp_buf;
	prefix_info.len = update->prefix_len;

	return del_fib_entry_numerical(&prefix_info, gk_conf);
}

void
kni_cps_route_event(struct cps_config *cps_conf)
{
	struct route_update updates[MAX_CPS_ROUTE_UPDATES];
	unsigned int i;
	unsigned int num_updates = 0;
	char buf[MNL_SOCKET_BUFFER_SIZE];

	do {
		int ret = mnl_socket_recvfrom_flags(cps_conf->nl, buf,
			sizeof(buf), MSG_DONTWAIT);
		if (ret == -1) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				RTE_LOG(ERR, GATEKEEPER,
					"cps: %s: recv: %s\n",
					__func__, strerror(errno));
			break;
		}

		ret = mnl_cb_run(buf, ret, 0, 0,
			route_cb, &updates[num_updates]);
		if (ret != MNL_CB_OK)
			break;

		if (updates[num_updates].valid)
			num_updates++;
	} while (num_updates < MAX_CPS_ROUTE_UPDATES);

	if (cps_conf->gk == NULL) {
		/*
		 * Grantor only runs CPS for ECMP support and
		 * shouldn't be receiving route updates.
		 */
		if (unlikely(num_updates != 0)) {
			RTE_LOG(WARNING, GATEKEEPER,
				"cps: the system is running as Grantor, and there shouldn't be any rtnetlink message processed under this configuration while receiving %u route update messages!\n",
				num_updates);
		}

		return;
	}

	for (i = 0; i < num_updates; i++) {
		if (updates[i].type == RTM_NEWROUTE)
			new_route(&updates[i], cps_conf);
		else if (likely(updates[i].type == RTM_DELROUTE))
			del_route(&updates[i], cps_conf->gk);
		else {
			RTE_LOG(WARNING, GATEKEEPER,
				"cps: receiving an unexpected update rule with type = %d!\n",
				updates[i].type);
		}
	}
}

/*
 * Inserting and removing modules.
 *
 * This code is adapted for use in DPDK from the source code of
 * insmod and rmmod in the module-init-tools package.
 */

static void *
grab_file(const char *filename, unsigned long *size)
{
	unsigned int kmod_size;
	struct stat stat_buf;
	char *buffer;
	int ret;

	int fd = open(filename, O_RDONLY, 0);
	if (fd < 0) {
		RTE_LOG(ERR, GATEKEEPER, "cps: open: %s\n", strerror(errno));
		return NULL;
	}

	ret = fstat(fd, &stat_buf);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER, "cps: fstat: %s\n", strerror(errno));
		goto close;
	}

	kmod_size = stat_buf.st_size;

	buffer = rte_malloc("kni_kmod", kmod_size, 0);
	if (buffer == NULL) {
		RTE_LOG(ERR, GATEKEEPER,
			"cps: couldn't allocate %u bytes to read %s\n",
			kmod_size, filename);
		goto close;
	}

	*size = 0;
	while ((ret = read(fd, buffer + *size, kmod_size - *size)) > 0)
		*size += ret;
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER, "cps: read: %s\n", strerror(errno));
		goto free;
	}

	RTE_VERIFY(*size == kmod_size);
	close(fd);
	return buffer;

free:
	rte_free(buffer);
close:
	close(fd);
	return NULL;
}

static const char *
moderror(int err)
{
	switch (err) {
	case ENOEXEC:
		return "Invalid module format";
	case ENOENT:
		return "Unknown symbol in module";
	case ESRCH:
		return "Module has wrong symbol version";
	case EINVAL:
		return "Invalid parameters";
	default:
		return strerror(err);
	}
}

int
init_kni(const char *kni_kmod_path, unsigned int num_kni)
{
	unsigned long len;
	int ret;

	void *file = grab_file(kni_kmod_path, &len);
	if (file == NULL) {
		RTE_LOG(ERR, GATEKEEPER, "insmod: can't read '%s'\n",
			kni_kmod_path);
		return -1;
	}

	ret = init_module(file, len, "");
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"insmod: error inserting '%s': %d %s\n",
			kni_kmod_path, ret, moderror(errno));
		rte_free(file);
		return ret;
	}
	rte_free(file);

	rte_kni_init(num_kni);
	return 0;
}

#define PROC_MODULES_FILENAME ("/proc/modules")

static int
check_usage(const char *modname)
{
	FILE *module_list;
	int found_mods = false;
	char line[10240], name[64];
	int ret = 0;

	module_list = fopen(PROC_MODULES_FILENAME, "r");
	if (module_list == NULL) {
		RTE_LOG(ERR, GATEKEEPER,
			"Can't open %s: %s\n", PROC_MODULES_FILENAME,
			strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), module_list) != NULL) {
		unsigned long size, refs;
		int scanned;

		found_mods = true;

		if (strchr(line, '\n') == NULL) {
			RTE_LOG(ERR, GATEKEEPER, "long line broke rmmod.\n");
			ret = -1;
			goto out;
		}

		/*
		 * Bound number of bytes written to @name; maximum
		 * field width does not include null terminator.
		 */
		scanned = sscanf(line, "%63s %lu %lu", name, &size, &refs);

		if (scanned <= 2 || scanned == EOF) {
			if (scanned < 2 || scanned == EOF)
				RTE_LOG(ERR, GATEKEEPER,
					"Unknown format in %s: %s\n",
					PROC_MODULES_FILENAME, line);
			else
				RTE_LOG(ERR, GATEKEEPER,
					"Kernel doesn't support unloading.\n");
			ret = -1;
			goto out;
		}

		if (strcmp(name, modname) != 0)
			continue;

		if (refs != 0) {
			RTE_LOG(ERR, GATEKEEPER,
				"Module %s is in use\n", modname);
			ret = -1;
		}

		goto out;
	}

	if (found_mods)
		RTE_LOG(ERR, GATEKEEPER,
			"Module %s does not exist in %s\n", modname,
			PROC_MODULES_FILENAME);
	else
		RTE_LOG(ERR, GATEKEEPER,
			"fgets: error in reading %s\n", PROC_MODULES_FILENAME);

	ret = -1;
out:
	fclose(module_list);
	return ret;
}

void
rm_kni(void)
{
	const char *name = "rte_kni";
	int ret;

	rte_kni_close();

	ret = check_usage(name);
	if (ret < 0)
		return;

	ret = delete_module(name, O_NONBLOCK);
	if (ret < 0)
		RTE_LOG(ERR, GATEKEEPER, "Error removing %s: %s\n",
			name, strerror(errno));
}

static void
cps_arp_cb(const struct lls_map *map, void *arg,
	__attribute__((unused)) enum lls_reply_ty ty, int *pcall_again)
{
	struct cps_config *cps_conf = get_cps_conf();
	struct cps_request *req;
	int ret;

	if (pcall_again != NULL)
		*pcall_again = false;
	else {
		/*
		 * Destination didn't reply, so this callback
		 * is the result of a call to put_arp().
		 */
		return;
	}
	RTE_VERIFY(!map->stale);

	/*
	 * If this allocation or queueing of an entry fails, the
	 * resolution request will time out after two iterations
	 * of the timer and be removed in cps_scan() anyway.
	 */

	req = mb_alloc_entry(&cps_conf->mailbox);
	if (req == NULL) {
		RTE_LOG(ERR, GATEKEEPER,
			"cps: %s: allocation of mailbox message failed\n",
			__func__);
		return;
	}

	req->ty = CPS_REQ_ARP;
	rte_memcpy(&req->u.arp.ip, map->ip_be, sizeof(req->u.arp.ip));
	rte_memcpy(&req->u.arp.ha, &map->ha, sizeof(req->u.arp.ha));
	req->u.arp.iface = arg;

	ret = mb_send_entry(&cps_conf->mailbox, req);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"cps: %s: failed to enqueue message to mailbox\n",
			__func__);
		return;
	}
}

void
kni_process_arp(struct cps_config *cps_conf, struct gatekeeper_if *iface,
	struct rte_mbuf *buf, const struct ether_hdr *eth_hdr)
{
	struct arp_hdr *arp_hdr;
	uint16_t pkt_len = rte_pktmbuf_data_len(buf);
	struct arp_request *arp_req;
	struct arp_request *entry;

	if (unlikely(!arp_enabled(cps_conf->lls))) {
		RTE_LOG(NOTICE, GATEKEEPER, "cps: KNI for %s iface received ARP packet, but the interface is not configured for ARP\n",
			iface->name);
		goto out;
	}

	if (unlikely(pkt_len < sizeof(*eth_hdr) + sizeof(*arp_hdr))) {
		RTE_LOG(ERR, GATEKEEPER, "cps: KNI received ARP packet of size %hu bytes, but it should be at least %zu bytes\n",
			pkt_len, sizeof(*eth_hdr) + sizeof(*arp_hdr));
		goto out;
	}

	arp_hdr = rte_pktmbuf_mtod_offset(buf, struct arp_hdr *,
		sizeof(*eth_hdr));

	/* If it's a Gratuitous ARP or reply, then no action is needed. */
	if (unlikely(rte_be_to_cpu_16(arp_hdr->arp_op) != ARP_OP_REQUEST ||
			is_garp_pkt(arp_hdr)))
		goto out;

	list_for_each_entry(entry, &cps_conf->arp_requests, list) {
		/* There's already a resolution request for this address. */
		if (arp_hdr->arp_data.arp_tip == entry->addr)
			goto out;
	}

	arp_req = rte_malloc(__func__, sizeof(*arp_req), 0);
	if (unlikely(entry == NULL)) {
		RTE_LOG(ERR, MALLOC, "%s: DPDK ran out of memory", __func__);
		goto out;
	}

	arp_req->addr = arp_hdr->arp_data.arp_tip;
	arp_req->stale = false;
	list_add_tail(&arp_req->list, &cps_conf->arp_requests);

	hold_arp(cps_arp_cb, iface,
		(struct in_addr *)&arp_hdr->arp_data.arp_tip,
		cps_conf->lcore_id);
out:
	rte_pktmbuf_free(buf);
}

static void
cps_nd_cb(const struct lls_map *map, void *arg,
	__attribute__((unused)) enum lls_reply_ty ty, int *pcall_again)
{
	struct cps_config *cps_conf = get_cps_conf();
	struct cps_request *req;
	int ret;

	if (pcall_again != NULL)
		*pcall_again = false;
	else {
		/*
		 * Destination didn't reply, so this callback
		 * is the result of a call to put_nd().
		 */
		return;
	}
	RTE_VERIFY(!map->stale);

	/*
	 * If this allocation or queueing of an entry fails, the
	 * resolution request will time out after two iterations
	 * of the timer and be removed anyway.
	 */

	req = mb_alloc_entry(&cps_conf->mailbox);
	if (req == NULL) {
		RTE_LOG(ERR, GATEKEEPER,
			"cps: %s: allocation of mailbox message failed\n",
			__func__);
		return;
	}

	req->ty = CPS_REQ_ND;
	rte_memcpy(&req->u.nd.ip, map->ip_be, sizeof(req->u.nd.ip));
	rte_memcpy(&req->u.nd.ha, &map->ha, sizeof(req->u.nd.ha));
	req->u.nd.iface = arg;

	ret = mb_send_entry(&cps_conf->mailbox, req);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"cps: %s: failed to enqueue message to mailbox\n",
			__func__);
		return;
	}
}

void
kni_process_nd(struct cps_config *cps_conf, struct gatekeeper_if *iface,
	struct rte_mbuf *buf, const struct ether_hdr *eth_hdr, uint16_t pkt_len)
{
	struct icmpv6_hdr *icmpv6_hdr;
	struct nd_neigh_msg *nd_msg;
	struct nd_request *nd_req;
	struct nd_request *entry;

	if (unlikely(!nd_enabled(cps_conf->lls))) {
		RTE_LOG(NOTICE, GATEKEEPER, "cps: KNI for %s iface received ND packet, but the interface is not configured for ND\n",
			iface->name);
		goto out;
	}

	if (pkt_len < ND_NEIGH_PKT_MIN_LEN(sizeof(*eth_hdr))) {
		RTE_LOG(NOTICE, GATEKEEPER, "cps: ND packet received is %"PRIx16" bytes but should be at least %lu bytes\n",
			pkt_len, ND_NEIGH_PKT_MIN_LEN(sizeof(*eth_hdr)));
		goto out;
	}

	icmpv6_hdr = rte_pktmbuf_mtod_offset(buf, struct icmpv6_hdr *,
		sizeof(*eth_hdr) + sizeof(struct ipv6_hdr));
	if (icmpv6_hdr->type == ND_NEIGHBOR_ADVERTISEMENT) {
		RTE_LOG(NOTICE, GATEKEEPER, "cps: ND Advertisement packet received from KNI attached to %s iface\n",
			iface->name);
		goto out;
	}

	nd_msg = (struct nd_neigh_msg *)&icmpv6_hdr[1];

	list_for_each_entry(entry, &cps_conf->nd_requests, list) {
		/* There's already a resolution request for this address. */
		if (ipv6_addrs_equal(nd_msg->target, entry->addr))
			goto out;
	}

	nd_req = rte_malloc(__func__, sizeof(*nd_req), 0);
	if (unlikely(entry == NULL)) {
		RTE_LOG(ERR, MALLOC, "%s: DPDK ran out of memory", __func__);
		goto out;
	}

	rte_memcpy(nd_req->addr, nd_msg->target, sizeof(nd_req->addr));
	nd_req->stale = false;
	list_add_tail(&nd_req->list, &cps_conf->nd_requests);

	hold_nd(cps_nd_cb, iface, (struct in6_addr *)nd_msg->target,
		cps_conf->lcore_id);
out:
	rte_pktmbuf_free(buf);
}
