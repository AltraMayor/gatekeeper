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
#include <net/if_arp.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_malloc.h>

#include "gatekeeper_cps.h"
#include "gatekeeper_lls.h"
#include "gatekeeper_main.h"
#include "elf.h"
#include "kni.h"

#define KNI_MODULE_NAME ("rte_kni")

/*
 * According to init_module(2) and delete_module(2), there
 * are no declarations for these functions in header files.
 */
extern long init_module(void *, unsigned long, const char *);
extern long delete_module(const char *, unsigned int);

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

	/* Route prefix length. */
	uint8_t  prefix_len;

	/* Route origin. See field rtm_protocol of struct rtmsg. */
	uint8_t  rt_proto;

	/* Output interface index of route. */
	uint32_t oif_index;

	/* IP address of route. */
	union {
		struct in_addr  v4;
		struct in6_addr v6;
	} ip;

	/* IP address of route gateway. */
	union {
		struct in_addr  v4;
		struct in6_addr v6;
	} gw;
};

int
kni_change_if(uint16_t port_id, uint8_t if_up)
{
	int ret = 0;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		CPS_LOG(ERR, "%s: invalid port ID %hu\n", __func__, port_id);
		return -EINVAL;
	}

	if (if_up != 0) {
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
		if (ret < 0)
			CPS_LOG(ERR, "%s: Failed to start port %hu\n",
				__func__, port_id);
	} else
		rte_eth_dev_stop(port_id);

	return ret;
}

int
kni_disable_change_mtu(__attribute__((unused)) uint16_t port_id,
__attribute__((unused)) unsigned int new_mtu)
{
	/*
	 * Gatekeeper does not support changing the MTU of its NICs.
	 * The MTU is set for both physical interfaces and the KNIs,
	 * and Gatekeeper performs encapsulation. Changing the MTU
	 * could have side effects on these features that are not
	 * yet fully considered so we disable MTU changes.
	 */
	return -ENOTSUP;
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
	int family, void *ipaddr, uint8_t prefixlen, const char *kni_name,
	unsigned int kni_index)
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
	ifa->ifa_index = kni_index;

	if (ifa->ifa_family == AF_INET)
		mnl_attr_put_u32(nlh, IFA_LOCAL, *(uint32_t *)ipaddr);
	else if (ifa->ifa_family == AF_INET6)
		mnl_attr_put(nlh, IFA_LOCAL, 16, ipaddr);
	else
		rte_panic("%s: address family (%d) not recognized\n",
			__func__, family);

	ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
	if (ret < 0) {
		CPS_LOG(ERR, "mnl_socket_sendto: cannot update %s with new IP address (family %d) (operation %d): %s\n",
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
		CPS_LOG(ERR, "mnl_socket_recvfrom: cannot update %s with new IP address (family %d) (operation %d): %s\n",
			kni_name, family, cmd, strerror(errno));
		return ret;
	}

	ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
	if (ret == -1) {
		CPS_LOG(ERR, "mnl_cb_run: cannot update %s with new IP address (family %d) (operation %d): %s\n",
			kni_name, family, cmd, strerror(errno));
		return ret;
	}

	return ret;
}

static int
add_ipaddr(struct mnl_socket *nl, int family, void *ipaddr,
	uint8_t prefixlen, const char *kni_name, unsigned int kni_index)
{
	return modify_ipaddr(nl, RTM_NEWADDR,
		NLM_F_CREATE|NLM_F_REQUEST|NLM_F_EXCL, family,
		ipaddr, prefixlen, kni_name, kni_index);
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
		CPS_LOG(ERR, "Fork failed, can't modify KNI %s link: %s\n",
			kni_name, strerror(errno));
		return -1;
	} else if (pid == 0) {
		/*
		 * Send request to kernel, which will be sent back
		 * to userspace for the parent to handle.
		 */
		int ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
		if (ret < 0) {
			CPS_LOG(ERR,
				"mnl_socket_sendto: cannot bring KNI %s %s: %s\n",
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
				CPS_LOG(ERR, "%s: error in handling userspace request\n",
					__func__);
				goto next;
			}

			/* Check if child has finished submitting request. */
			ret = waitpid(pid, &status, WNOHANG);
			if (ret == 0) {
				/* Keep trying to handle the KNI request. */
				goto next;
			} else if (ret == -1) {
				CPS_LOG(ERR, "waitpid: %s\n", strerror(errno));
				goto kill;
			}

			ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
			if (ret == -1) {
				CPS_LOG(ERR, "mnl_socket_recvfrom: cannot bring KNI %s %s: %s\n",
					kni_name, if_up ? "up" : "down",
					strerror(errno));
				return ret;
			}

			ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
			if (ret == -1) {
				CPS_LOG(ERR, "mnl_cb_run: cannot bring KNI %s %s: %s\n",
					kni_name, if_up ? "up" : "down",
					strerror(errno));
				return ret;
			}

			return 0;
next:
			attempts++;
			sleep(1);
		} while (attempts < get_cps_conf()->num_attempts_kni_link_set);
	}
kill:
	/* Failed to wait for child or waited for too many attempts. */
	kill(pid, SIGTERM);
	return -1;
}

int
kni_config_ip_addrs(struct rte_kni *kni, unsigned int kni_index,
	struct gatekeeper_if *iface)
{
	struct mnl_socket *nl;
	const char *kni_name = rte_kni_get_name(kni);
	int ret = 0;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		CPS_LOG(ERR, "mnl_socket_open: %s\n", strerror(errno));
		return -1;
	}

	ret = mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
	if (ret < 0) {
		CPS_LOG(ERR, "mnl_socket_bind: %s\n", strerror(errno));
		goto close;
	}

	/* Add global and link-local IP addresses. */
	if (ipv4_if_configured(iface)) {
		ret = add_ipaddr(nl, AF_INET, &iface->ip4_addr,
			iface->ip4_addr_plen, kni_name, kni_index);
		if (ret < 0)
			goto close;
	}

	if (ipv6_if_configured(iface)) {
		ret = add_ipaddr(nl, AF_INET6, &iface->ip6_addr,
			iface->ip6_addr_plen, kni_name, kni_index);
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
		CPS_LOG(ERR, "mnl_socket_open: %s\n", strerror(errno));
		return -1;
	}

	ret = mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
	if (ret < 0) {
		CPS_LOG(ERR, "mnl_socket_bind: %s\n", strerror(errno));
		goto close;
	}

	/* Bring interface up. */
	ret = modify_link(nl, kni, kni_name, true);

close:
	mnl_socket_close(nl);
	return ret;
}

/* The below rd_*() functions handle interactions with the routing daemon. */

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
		CPS_LOG(ERR, "%s: mnl_socket_open: %s\n",
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
		CPS_LOG(ERR, "%s: mnl_socket_bind: %s\n",
			__func__, strerror(errno));
		goto close;
	}

	return 0;

close:
	rd_event_sock_close(cps_conf);
	return ret;
}

static inline void
inet_print(const char *msg, struct in_addr *in)
{
	char buf[INET_ADDRSTRLEN];
	CPS_LOG(DEBUG, "cps update: %s: %s\n", msg,
		inet_ntop(AF_INET, &in->s_addr, buf, sizeof(buf)));
}

static inline void
inet6_print(const char *msg, struct in6_addr *in6)
{
	char buf[INET6_ADDRSTRLEN];
	CPS_LOG(DEBUG, "cps update: %s: %s\n", msg,
		inet_ntop(AF_INET6, &in6->s6_addr, buf, sizeof(buf)));
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
		CPS_LOG(WARNING,
			"cps update: unknown address family %d at %s\n",
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
			if (update->oif_index != cps_conf->front_kni_index) {
				CPS_LOG(WARNING,
					"The output KNI interface for prefix %s is not the front interface while the gateway for the prefix in Gatekeeper is a neighbor of the front network\n",
					prefix_info.str);
				return -1;
			}
		}

		return add_fib_entry_numerical(&prefix_info, NULL, &gw_addr,
			GK_FWD_GATEWAY_FRONT_NET, update->rt_proto,
			cps_conf->gk);
	}

	if (gw_fib->action == GK_FWD_NEIGHBOR_BACK_NET) {
		if (update->oif_index != 0) {
			if (update->oif_index != cps_conf->back_kni_index) {
				CPS_LOG(WARNING,
					"The output KNI interface for prefix %s is not the back interface while the gateway for the prefix in Gatekeeper is a neighbor of the back network\n",
					prefix_info.str);
				return -1;
			}
		}

		return add_fib_entry_numerical(&prefix_info, NULL, &gw_addr,
			GK_FWD_GATEWAY_BACK_NET, update->rt_proto,
			cps_conf->gk);
	}

	return -1;
}

static int
del_route(struct route_update *update, struct cps_config *cps_conf)
{
	int ret;
	char ip_buf[INET6_ADDRSTRLEN];
	char ipp_buf[INET6_ADDRSTRLEN + 4];
	struct ip_prefix prefix_info;
	struct gk_config *gk_conf = cps_conf->gk;

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
		CPS_LOG(WARNING,
			"cps update: unknown address family %d at %s\n",
			update->family, __func__);
		return -1;
	}

	prefix_info.str = ipp_buf;
	prefix_info.len = update->prefix_len;

	return del_fib_entry_numerical(&prefix_info, gk_conf);
}

static int
attr_get(struct route_update *update, int family, struct nlattr *tb[])
{
	bool dst_present = false;
	bool gw_present = false;
	bool oif_present = false;

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
		CPS_LOG(DEBUG, "cps update: multipath\n");
	}
	if (tb[RTA_DST]) {
		if (family == AF_INET) {
			struct in_addr *addr =
				mnl_attr_get_payload(tb[RTA_DST]);
			rte_memcpy(&update->ip.v4,
				addr, sizeof(update->ip.v4));
			inet_print("dst", addr);
		} else if (likely(family == AF_INET6)) {
			struct in6_addr *addr =
				mnl_attr_get_payload(tb[RTA_DST]);
			rte_memcpy(&update->ip.v6,
				addr, sizeof(update->ip.v6));
			inet6_print("dst", addr);
		} else {
			CPS_LOG(WARNING,
				"cps update: unknown address family %d at %s\n",
				family, __func__);
			return -EAFNOSUPPORT;
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
				int saved_errno = errno;
				CPS_LOG(ERR,
					"%s: failed to convert a number to an IPv4 address (%s)\n",
					__func__, strerror(errno));
				return -saved_errno; 
			}
		} else if (likely(family == AF_INET6)) {
			struct in6_addr *addr =
				mnl_attr_get_payload(tb[RTA_SRC]);
			if (inet_ntop(AF_INET6, &addr->s6_addr, buf,
					sizeof(buf)) == NULL) {
				int saved_errno = errno;
				CPS_LOG(ERR,
					"%s: failed to convert a number to an IPv6 address (%s)\n",
					__func__, strerror(errno));
				return -saved_errno; 
			}
		} else {
			CPS_LOG(WARNING,
				"cps update: unknown address family %d at %s\n",
				family, __func__);
			return -EAFNOSUPPORT;
		}

		CPS_LOG(WARNING,
			"cps update: the rtnetlink command has information (RTA_SRC with IP address %s) that we don't need or don't honor\n",
			buf);
	}
	if (tb[RTA_OIF]) {
		update->oif_index = mnl_attr_get_u32(tb[RTA_OIF]);
		CPS_LOG(DEBUG, "cps update: oif=%u\n", update->oif_index);
		oif_present = true;
	}
	if (tb[RTA_FLOW]) {
		CPS_LOG(WARNING,
			"cps update: the rtnetlink command has information (RTA_FLOW with flow=%u) that we don't need or don't honor\n",
			mnl_attr_get_u32(tb[RTA_FLOW]));
	}
	if (tb[RTA_PREFSRC]) {
		char buf[INET6_ADDRSTRLEN];

		if (family == AF_INET) {
			struct in_addr *addr =
				mnl_attr_get_payload(tb[RTA_PREFSRC]);
			if (inet_ntop(AF_INET, &addr->s_addr, buf,
					sizeof(buf)) == NULL) {
				int saved_errno = errno;
				CPS_LOG(ERR,
					"%s: failed to convert a number to an IPv4 address (%s)\n",
					__func__, strerror(errno));
				return -saved_errno;
			}
		} else if (likely(family == AF_INET6)) {
			struct in6_addr *addr =
				mnl_attr_get_payload(tb[RTA_PREFSRC]);
			if (inet_ntop(AF_INET6, &addr->s6_addr, buf,
					sizeof(buf)) == NULL) {
				int saved_errno = errno;
				CPS_LOG(ERR,
					"%s: failed to convert a number to an IPv6 address (%s)\n",
					__func__, strerror(errno));
				return -saved_errno;
			}
		} else {
			CPS_LOG(WARNING,
				"cps update: unknown address family %d at %s\n",
				family, __func__);
			return -EAFNOSUPPORT;
		}

		CPS_LOG(WARNING,
			"cps update: the rtnetlink command has information (RTA_PREFSRC with IP address %s) that we don't need or don't honor\n",
			buf);
	}
	if (tb[RTA_GATEWAY]) {
		if (family == AF_INET) {
			struct in_addr *addr =
				mnl_attr_get_payload(tb[RTA_GATEWAY]);
			rte_memcpy(&update->gw.v4,
				addr, sizeof(update->gw.v4));
			inet_print("gw", addr);
		} else if (likely(family == AF_INET6)) {
			struct in6_addr *addr =
				mnl_attr_get_payload(tb[RTA_GATEWAY]);
			rte_memcpy(&update->gw.v6,
				addr, sizeof(update->gw.v6));
			inet6_print("gw", addr);
		} else {
			CPS_LOG(WARNING,
				"cps update: unknown address family %d at %s\n",
				family, __func__);
			return -EAFNOSUPPORT;
		}

		gw_present = true;
	}
	if (tb[RTA_PRIORITY]) {
		CPS_LOG(WARNING,
			"cps update: the rtnetlink command has information (RTA_PRIORITY with prio=%u) that we don't need or don't honor\n",
			mnl_attr_get_u32(tb[RTA_PRIORITY]));
	}

	update->valid = dst_present &&
		(update->type == RTM_DELROUTE ||
		(update->type == RTM_NEWROUTE && gw_present && oif_present));
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

	if (sendto(mnl_socket_get_fd(cps_conf->rd_nl),
			rep, sizeof(*rep) + errmsg_len, 0,
			(struct sockaddr *)&rd_sa, sizeof(rd_sa)) < 0) {
		CPS_LOG(ERR, "sendto: cannot send NLMSG_ERROR to daemon (pid=%u seq=%u): %s\n",
			req->nlmsg_pid, req->nlmsg_seq,
			strerror(errno));
	}
}

static void
rd_fill_getroute_reply(struct cps_config *cps_conf, struct nlmsghdr *reply,
	struct gk_fib *fib, int family, uint32_t seq,
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
	rm->rtm_type = RTN_UNICAST;
	rm->rtm_flags = 0;

	switch (fib->action) {
	case GK_FWD_GRANTOR:
		mnl_attr_put_u32(reply, RTA_OIF, cps_conf->back_kni_index);
		rm->rtm_protocol = RTPROT_STATIC;
		*gw_addr = &fib->u.grantor.eth_cache->ip_addr;
		break;
	case GK_FWD_GATEWAY_FRONT_NET:
		mnl_attr_put_u32(reply, RTA_OIF, cps_conf->front_kni_index);
		rm->rtm_protocol = fib->u.gateway.rt_proto;
		*gw_addr = &fib->u.gateway.eth_cache->ip_addr;
		break;
	case GK_FWD_GATEWAY_BACK_NET:
		mnl_attr_put_u32(reply, RTA_OIF, cps_conf->back_kni_index);
		rm->rtm_protocol = fib->u.gateway.rt_proto;
		*gw_addr = &fib->u.gateway.eth_cache->ip_addr;
		break;
	case GK_FWD_NEIGHBOR_FRONT_NET:
		mnl_attr_put_u32(reply, RTA_OIF, cps_conf->front_kni_index);
		rm->rtm_protocol = RTPROT_STATIC;
		*gw_addr = NULL;
		break;
	case GK_FWD_NEIGHBOR_BACK_NET:
		mnl_attr_put_u32(reply, RTA_OIF, cps_conf->back_kni_index);
		rm->rtm_protocol = RTPROT_STATIC;
		*gw_addr = NULL;
		break;
	default:
		rte_panic("Invalid FIB action (%u) in FIB while being processed by CPS block in %s\n",
			fib->action, __func__);
		return;
	}
}

static int
rd_send_batch(const struct cps_config *cps_conf, struct mnl_nlmsg_batch *batch,
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

	if (sendto(mnl_socket_get_fd(cps_conf->rd_nl),
			mnl_nlmsg_batch_head(batch),
			mnl_nlmsg_batch_size(batch), 0,
			(struct sockaddr *)&rd_sa, sizeof(rd_sa)) < 0) {
		ret = -errno;
		CPS_LOG(ERR,
			"sendto: cannot dump route batch to %s daemon (pid=%u seq=%u): %s\n",
			daemon, pid, seq, strerror(errno));
	}

	mnl_nlmsg_batch_reset(batch);
	return ret;
}

static int
rd_getroute_ipv4_locked(struct cps_config *cps_conf, struct gk_lpm *ltbl,
	struct mnl_nlmsg_batch *batch, const struct nlmsghdr *req, int family)
{
	struct rte_lpm_iterator_state state;
	const struct rte_lpm_rule *re4;
	int index;

	int ret = rte_lpm_iterator_state_init(ltbl->lpm, 0, 0, &state);
	if (ret < 0) {
		CPS_LOG(ERR, "Failed to initialize the IPv4 LPM rule iterator state in %s\n",
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
			family, req->nlmsg_seq, state.depth, &gw_addr);

		/* Add address. */
		mnl_attr_put_u32(reply, RTA_DST, htonl(re4->ip));

		/* Only report gateway for main routes. */
		if (gw_addr != NULL) {
			mnl_attr_put_u32(reply, RTA_GATEWAY,
				gw_addr->ip.v4.s_addr);
		}

		if (!mnl_nlmsg_batch_next(batch)) {
			ret = rd_send_batch(cps_conf, batch, "IPv4",
				req->nlmsg_seq, req->nlmsg_pid, false);
			if (ret < 0)
				return ret;
		}

		index = rte_lpm_rule_iterate(&state, &re4);
	}

	return 0;
}

static int
rd_getroute_ipv6_locked(struct cps_config *cps_conf, struct gk_lpm *ltbl,
	struct mnl_nlmsg_batch *batch, const struct nlmsghdr *req, int family)
{
	struct rte_lpm6_iterator_state state6;
	struct rte_lpm6_rule re6;
	int index;

	int ret = rte_lpm6_iterator_state_init(ltbl->lpm6, 0, 0, &state6);
	if (ret < 0) {
		CPS_LOG(ERR, "Failed to initialize the IPv6 LPM rule iterator state in %s\n",
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
			family, req->nlmsg_seq, state6.depth, &gw_addr);

		/* Add address. */
		mnl_attr_put(reply, RTA_DST,
			sizeof(struct in6_addr), re6.ip);

		/* Only report gateway for main routes. */
		if (gw_addr != NULL) {
			mnl_attr_put(reply, RTA_GATEWAY,
				sizeof(struct in6_addr), &gw_addr->ip.v6);
		}

		if (!mnl_nlmsg_batch_next(batch)) {
			ret = rd_send_batch(cps_conf, batch, "IPv6",
				req->nlmsg_seq, req->nlmsg_pid, false);
			if (ret < 0)
				return ret;
		}

		index = rte_lpm6_rule_iterate(&state6, &re6);
	}

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
		CPS_LOG(ERR, "Not enough room in CPS GETROUTE message from routing daemon in %s\n",
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
		CPS_LOG(ERR, "Unsupported address family type (%d) in %s\n",
			family, __func__);
		*err = -EAFNOSUPPORT;
		goto out;
	}

	batch = mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);
	if (batch == NULL) {
		CPS_LOG(ERR, "Failed to allocate a batch for a GETROUTE reply\n");
		*err = -ENOMEM;
		goto out;
	}

	if (family == AF_INET || family == AF_UNSPEC) {
		rte_spinlock_lock_tm(&ltbl->lock);
		*err = rd_getroute_ipv4_locked(cps_conf, ltbl,
			batch, req, family);
		rte_spinlock_unlock_tm(&ltbl->lock);
		if (*err < 0)
			goto free_batch;
	}

	if (family == AF_INET6 || family == AF_UNSPEC) {
		rte_spinlock_lock_tm(&ltbl->lock);
		*err = rd_getroute_ipv6_locked(cps_conf, ltbl,
			batch, req, family);
		rte_spinlock_unlock_tm(&ltbl->lock);
		if (*err < 0)
			goto free_batch;
	}

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
	ifim->ifi_flags = 0;
	ifim->ifi_change = 0xFFFFFFFF;

	mnl_attr_put_str(reply, IFLA_IFNAME, kni_name);
	mnl_attr_put_u32(reply, IFLA_MTU, kni_mtu);
}

static int
rd_getlink(const struct nlmsghdr *req, const struct cps_config *cps_conf,
	int *err)
{
	char buf[2 * MNL_SOCKET_BUFFER_SIZE];
	struct mnl_nlmsg_batch *batch;

	batch = mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);
	if (batch == NULL) {
		CPS_LOG(ERR, "Failed to allocate a batch for a GETLINK reply\n");
		*err = -ENOMEM;
		goto out;
	}

	rd_fill_getlink_reply(cps_conf, batch,
		rte_kni_get_name(cps_conf->front_kni),
		cps_conf->front_kni_index, kni_mtu(&cps_conf->net->front),
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
			kni_mtu(&cps_conf->net->back), req->nlmsg_seq);
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
rd_modroute(const struct nlmsghdr *req, struct cps_config *cps_conf, int *err)
{
	struct nlattr *tb[__RTA_MAX] = {};
	struct rtmsg *rm = mnl_nlmsg_get_payload(req);
	struct route_update update;

	if (unlikely(cps_conf->gk == NULL)) {
		/*
		 * Grantor only runs CPS for ECMP support and
		 * shouldn't be receiving route updates.
		 */
		CPS_LOG(WARNING,
			"The system is running as Grantor, and there shouldn't be any rtnetlink message processed under this configuration while receiving route update messages\n");
		*err = -EOPNOTSUPP;
		goto out;
	}

	CPS_LOG(DEBUG, "cps update: [%s] family=%u dst_len=%u src_len=%u tos=%u table=%u protocol=%u scope=%u type=%u flags=%x\n",
		req->nlmsg_type == RTM_NEWROUTE ? "NEW" : "DEL",
		rm->rtm_family, rm->rtm_dst_len, rm->rtm_src_len,
		rm->rtm_tos, rm->rtm_table, rm->rtm_protocol,
		rm->rtm_protocol, rm->rtm_scope, rm->rtm_flags);

	memset(&update, 0, sizeof(update));
	update.valid = false;
	update.type = req->nlmsg_type;
	update.family = rm->rtm_family;

	/* Destination prefix length, e.g., 24 or 32 for IPv4. */
	update.prefix_len = rm->rtm_dst_len;

	/* Default to an invalid index number. */
	update.oif_index = 0;

	/* Route origin (routing daemon). */
	update.rt_proto = rm->rtm_protocol;

	switch(rm->rtm_family) {
	case AF_INET:
		mnl_attr_parse(req, sizeof(*rm), data_ipv4_attr_cb, tb);
		*err = attr_get(&update, rm->rtm_family, tb);
		if (*err)
			goto out;
		break;
	case AF_INET6:
		mnl_attr_parse(req, sizeof(*rm), data_ipv6_attr_cb, tb);
		*err = attr_get(&update, rm->rtm_family, tb);
		if (*err)
			goto out;
		break;
	default:
		CPS_LOG(NOTICE, "Unrecognized family in netlink event: %u\n",
			rm->rtm_family);
		*err = -EAFNOSUPPORT;
		goto out;
	}

	if (update.valid) {
		if (update.type == RTM_NEWROUTE)
			*err = new_route(&update, cps_conf);
		else if (likely(update.type == RTM_DELROUTE))
			*err = del_route(&update, cps_conf);
		else {
			CPS_LOG(WARNING, "Receiving an unexpected update rule with type = %d\n",
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
rd_getaddr_iface(const struct cps_config *cps_conf,
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
rd_getaddr(const struct nlmsghdr *req, const struct cps_config *cps_conf,
	int *err)
{
	char buf[2 * MNL_SOCKET_BUFFER_SIZE];
	struct mnl_nlmsg_batch *batch;
	struct net_config *net_conf = cps_conf->net;
	int family;
	const char *family_str;

	if (mnl_nlmsg_get_payload_len(req) < sizeof(struct rtgenmsg)) {
		CPS_LOG(ERR, "Not enough room in CPS GETADDR message from routing daemon in %s\n",
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
		CPS_LOG(ERR, "Unsupported address family type (%d) in %s\n",
			family, __func__);
		*err = -EAFNOSUPPORT;
		goto out;
	}

	batch = mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);
	if (batch == NULL) {
		CPS_LOG(ERR, "Failed to allocate a batch for a GETADDR reply\n");
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
		CPS_LOG(NOTICE, "Unrecognized netlink message type: %u\n",
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
kni_cps_rd_event(struct cps_config *cps_conf)
{
	unsigned int update_pkts = cps_conf->max_rt_update_pkts;
	do {
		char buf[MNL_SOCKET_BUFFER_SIZE];
		int ret = mnl_socket_recvfrom_flags(cps_conf->rd_nl, buf,
			sizeof(buf), MSG_DONTWAIT);
		if (ret == -1) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				CPS_LOG(ERR, "%s: recv: %s\n",
					__func__, strerror(errno));
			break;
		}

		ret = mnl_cb_run(buf, ret, 0, 0, rd_cb, cps_conf);
		if (ret != MNL_CB_OK)
			break;

		update_pkts--;
	} while (update_pkts > 0);
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
		CPS_LOG(ERR, "open: %s\n", strerror(errno));
		return NULL;
	}

	ret = fstat(fd, &stat_buf);
	if (ret < 0) {
		CPS_LOG(ERR, "fstat: %s\n", strerror(errno));
		goto close;
	}

	kmod_size = stat_buf.st_size;

	buffer = rte_malloc("kni_kmod", kmod_size, 0);
	if (buffer == NULL) {
		CPS_LOG(ERR, "Couldn't allocate %u bytes to read %s\n",
			kmod_size, filename);
		goto close;
	}

	*size = 0;
	while ((ret = read(fd, buffer + *size, kmod_size - *size)) > 0)
		*size += ret;
	if (ret < 0) {
		CPS_LOG(ERR, "read: %s\n", strerror(errno));
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

#define SYS_MODULES_ATTR_PATH ("/sys/module/%s/%s")

static int
get_loaded_kmod_attr(const char *attr, char *val, size_t val_len)
{
	FILE *attr_file;
	char path[256];
	char line[1024];
	int ret;

	ret = snprintf(path, sizeof(path), SYS_MODULES_ATTR_PATH,
		KNI_MODULE_NAME, attr);
	if (ret <= 0 || ret >= (int)sizeof(path)) {
		CPS_LOG(ERR, "Can't compose path name to read %s from loaded %s\n",
			attr, KNI_MODULE_NAME);
		return -1;
	}

	attr_file = fopen(path, "r");
	if (attr_file == NULL) {
		CPS_LOG(ERR, "Can't open %s: %s\n", path, strerror(errno));
		return -1;
	}

	if (fgets(line, sizeof(line), attr_file) != NULL) {
		size_t len = strlen(line);

		/* fgets() reads in line, including newline character. */
		if (line[len - 1] != '\n') {
			CPS_LOG(ERR, "Line buffer too short to read in %s from %s\n",
				attr, path);
			ret = -1;
			goto close;
		}

		/* Remove newline. */
		line[len - 1] = '\0';
		len--;

		if (len > val_len - 1) {
			CPS_LOG(ERR, "Found attribute in %s but value buffer is too short to read in its value (%s)\n",
				path, line);
			ret = -1;
			goto close;
		}

		strcpy(val, line);
		ret = 0;
	} else
		ret = -1;

close:
	fclose(attr_file);
	return ret;
}

static bool
loaded_kmod_matches_file(void *file, unsigned long len)
{
	char kmod_srcver[64], loaded_kmod_srcver[64];
	int ret;

	ret = get_modinfo_string(file, len, "srcversion",
		kmod_srcver, sizeof(kmod_srcver));
	if (ret < 0) {
		CPS_LOG(ERR, "Unable to fetch srcversion of %s.ko file specified in config\n",
			KNI_MODULE_NAME);
		return false;
	}

	ret = get_loaded_kmod_attr("srcversion",
		loaded_kmod_srcver, sizeof(loaded_kmod_srcver));
	if (ret < 0) {
		CPS_LOG(ERR, "Unable to fetch srcversion of %s module already loaded\n",
			KNI_MODULE_NAME);
		return false;
	}

	if (strcmp(kmod_srcver, loaded_kmod_srcver) == 0)
		return true;

	CPS_LOG(ERR, "srcversion of loaded %s module (%s) does not match srcversion of %s.ko file specified in config (%s)\n",
		KNI_MODULE_NAME, loaded_kmod_srcver,
		KNI_MODULE_NAME, kmod_srcver);
	return false;
}

int
init_kni(const char *kni_kmod_path, unsigned int num_kni)
{
	unsigned long len;
	int ret;

	void *file = grab_file(kni_kmod_path, &len);
	if (file == NULL) {
		CPS_LOG(ERR, "%s: can't read '%s'\n", __func__, kni_kmod_path);
		return -1;
	}

	ret = init_module(file, len, "");
	if (ret < 0) {
		if (errno == EEXIST) {
			CPS_LOG(NOTICE, "%s: %s already inserted\n",
				__func__, kni_kmod_path);

			if (loaded_kmod_matches_file(file, len)) {
				ret = 0;
				goto success;
			}
		} else {
			CPS_LOG(ERR, "%s: error inserting '%s': %d %s\n",
				__func__, kni_kmod_path, ret, moderror(errno));
		}

		goto out;
	}

success:
	rte_kni_init(num_kni);
out:
	rte_free(file);
	return ret;
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
		CPS_LOG(ERR, "Can't open %s: %s\n", PROC_MODULES_FILENAME,
			strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), module_list) != NULL) {
		unsigned long size, refs;
		int scanned;

		found_mods = true;

		if (strchr(line, '\n') == NULL) {
			CPS_LOG(ERR, "Line too long while reading loaded modules file %s\n",
				PROC_MODULES_FILENAME);
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
				CPS_LOG(ERR, "Unknown format in %s: %s\n",
					PROC_MODULES_FILENAME, line);
			else
				CPS_LOG(ERR,
					"Kernel doesn't support unloading\n");
			ret = -1;
			goto out;
		}

		if (strcmp(name, modname) != 0)
			continue;

		if (refs != 0) {
			CPS_LOG(ERR, "Module %s is in use\n", modname);
			ret = -1;
		}

		goto out;
	}

	if (found_mods)
		CPS_LOG(ERR, "Module %s does not exist in %s\n", modname,
			PROC_MODULES_FILENAME);
	else
		CPS_LOG(ERR, "fgets: error in reading %s\n",
			PROC_MODULES_FILENAME);

	ret = -1;
out:
	fclose(module_list);
	return ret;
}

void
rm_kni(void)
{
	const char *name = KNI_MODULE_NAME;
	int ret;

	rte_kni_close();

	ret = check_usage(name);
	if (ret < 0)
		return;

	ret = delete_module(name, O_NONBLOCK);
	if (ret < 0)
		CPS_LOG(ERR, "Error removing %s: %s\n", name, strerror(errno));
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
		CPS_LOG(ERR, "%s: allocation of mailbox message failed\n",
			__func__);
		return;
	}

	req->ty = CPS_REQ_ARP;
	req->u.arp.ip = map->addr.ip.v4.s_addr;
	rte_memcpy(&req->u.arp.ha, &map->ha, sizeof(req->u.arp.ha));
	req->u.arp.iface = arg;

	ret = mb_send_entry(&cps_conf->mailbox, req);
	if (ret < 0) {
		CPS_LOG(ERR, "%s: failed to enqueue message to mailbox\n",
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
		CPS_LOG(NOTICE, "KNI for %s iface received ARP packet, but the interface is not configured for ARP\n",
			iface->name);
		goto out;
	}

	if (unlikely(pkt_len < sizeof(*eth_hdr) + sizeof(*arp_hdr))) {
		CPS_LOG(ERR, "KNI received ARP packet of size %hu bytes, but it should be at least %zu bytes\n",
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
		CPS_LOG(ERR, "%s: DPDK ran out of memory", __func__);
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
		CPS_LOG(ERR, "%s: allocation of mailbox message failed\n",
			__func__);
		return;
	}

	req->ty = CPS_REQ_ND;
	rte_memcpy(req->u.nd.ip, map->addr.ip.v6.s6_addr,
		sizeof(req->u.nd.ip));
	rte_memcpy(&req->u.nd.ha, &map->ha, sizeof(req->u.nd.ha));
	req->u.nd.iface = arg;

	ret = mb_send_entry(&cps_conf->mailbox, req);
	if (ret < 0) {
		CPS_LOG(ERR, "%s: failed to enqueue message to mailbox\n",
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
		CPS_LOG(NOTICE, "KNI for %s iface received ND packet, but the interface is not configured for ND\n",
			iface->name);
		goto out;
	}

	if (pkt_len < ND_NEIGH_PKT_MIN_LEN(sizeof(*eth_hdr))) {
		CPS_LOG(NOTICE, "ND packet received is %"PRIx16" bytes but should be at least %lu bytes\n",
			pkt_len, ND_NEIGH_PKT_MIN_LEN(sizeof(*eth_hdr)));
		goto out;
	}

	icmpv6_hdr = rte_pktmbuf_mtod_offset(buf, struct icmpv6_hdr *,
		sizeof(*eth_hdr) + sizeof(struct ipv6_hdr));
	if (icmpv6_hdr->type == ND_NEIGHBOR_ADVERTISEMENT) {
		CPS_LOG(NOTICE, "ND Advertisement packet received from KNI attached to %s iface\n",
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
		CPS_LOG(ERR, "%s: DPDK ran out of memory", __func__);
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
