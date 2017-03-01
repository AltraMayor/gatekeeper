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
#include "gatekeeper_main.h"
#include "kni.h"

/* Number of times to attempt bring a KNI interface up or down. */
#define NUM_ATTEMPTS_KNI_LINK_SET (5)

/*
 * According to init_module(2) and delete_module(2), there
 * are no declarations for these functions in header files.
 */
extern long init_module(void *, unsigned long, const char *);
extern long delete_module(const char *, unsigned int);

int
kni_change_if(uint8_t port_id, uint8_t if_up)
{
	return (if_up)
		? rte_eth_dev_set_link_up(port_id)
		: rte_eth_dev_set_link_down(port_id);
}

int
kni_change_mtu(uint8_t port_id, unsigned new_mtu)
{
	if (unlikely((new_mtu < ETHER_MIN_MTU) ||
			(new_mtu > ETHER_MAX_JUMBO_FRAME_LEN -
				(ETHER_HDR_LEN + ETHER_CRC_LEN))))
		return -EINVAL;

	return rte_eth_dev_set_mtu(port_id, new_mtu);
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
kni_config(struct rte_kni *kni, struct gatekeeper_if *iface)
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

	/* Bring interface up. */
	ret = modify_link(nl, kni, kni_name, true);

close:
	mnl_socket_close(nl);
	return ret;
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
