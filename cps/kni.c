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

#include <fcntl.h>
#include <libkmod.h>
#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/utsname.h>
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

int
kni_ignore_change(__attribute__((unused)) uint16_t port_id,
	__attribute__((unused)) uint8_t to_on)
{
	/*
	 * Silently ignore the request instead of returning -ENOTSUP to avoid
	 * upsetting applications.
	 */
	return 0;
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
	else if (likely(ifa->ifa_family == AF_INET6))
		mnl_attr_put(nlh, IFA_LOCAL, 16, ipaddr);
	else
		rte_panic("%s: address family (%d) not recognized\n",
			__func__, family);

	ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
	if (ret < 0) {
		G_LOG(ERR, "mnl_socket_sendto: cannot update %s with new IP address (family %d) (operation %d): %s\n",
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
		G_LOG(ERR, "mnl_socket_recvfrom: cannot update %s with new IP address (family %d) (operation %d): %s\n",
			kni_name, family, cmd, strerror(errno));
		return ret;
	}

	ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
	if (ret == -1) {
		G_LOG(ERR, "mnl_cb_run: cannot update %s with new IP address (family %d) (operation %d): %s\n",
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

	mnl_attr_put_strz(nlh, IFLA_IFNAME, kni_name);

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
		G_LOG(ERR, "Fork failed, can't modify KNI %s link: %s\n",
			kni_name, strerror(errno));
		return -1;
	} else if (pid == 0) {
		/*
		 * Send request to kernel, which will be sent back
		 * to userspace for the parent to handle.
		 */
		int ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
		if (ret < 0) {
			G_LOG(ERR,
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
				G_LOG(ERR, "%s: error in handling userspace request\n",
					__func__);
				goto next;
			}

			/* Check if child has finished submitting request. */
			ret = waitpid(pid, &status, WNOHANG);
			if (ret == 0) {
				/* Keep trying to handle the KNI request. */
				goto next;
			} else if (ret == -1) {
				G_LOG(ERR, "waitpid: %s\n", strerror(errno));
				goto kill;
			}

			ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
			if (ret == -1) {
				G_LOG(ERR, "mnl_socket_recvfrom: cannot bring KNI %s %s: %s\n",
					kni_name, if_up ? "up" : "down",
					strerror(errno));
				return ret;
			}

			ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
			if (ret == -1) {
				G_LOG(ERR, "mnl_cb_run: cannot bring KNI %s %s: %s\n",
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
		G_LOG(ERR, "mnl_socket_open: %s\n", strerror(errno));
		return -1;
	}

	ret = mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
	if (ret < 0) {
		G_LOG(ERR, "mnl_socket_bind: %s\n", strerror(errno));
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
		G_LOG(ERR, "mnl_socket_open: %s\n", strerror(errno));
		return -1;
	}

	ret = mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
	if (ret < 0) {
		G_LOG(ERR, "mnl_socket_bind: %s\n", strerror(errno));
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
		G_LOG(ERR, "open: %s\n", strerror(errno));
		return NULL;
	}

	ret = fstat(fd, &stat_buf);
	if (ret < 0) {
		G_LOG(ERR, "fstat: %s\n", strerror(errno));
		goto close;
	}

	kmod_size = stat_buf.st_size;

	buffer = rte_malloc("kni_kmod", kmod_size, 0);
	if (buffer == NULL) {
		G_LOG(ERR, "Couldn't allocate %u bytes to read %s\n",
			kmod_size, filename);
		goto close;
	}

	*size = 0;
	while ((ret = read(fd, buffer + *size, kmod_size - *size)) > 0)
		*size += ret;
	if (ret < 0) {
		G_LOG(ERR, "read: %s\n", strerror(errno));
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
		G_LOG(ERR, "Can't compose path name to read %s from loaded %s\n",
			attr, KNI_MODULE_NAME);
		return -1;
	}

	attr_file = fopen(path, "r");
	if (attr_file == NULL) {
		G_LOG(ERR, "Can't open %s: %s\n", path, strerror(errno));
		return -1;
	}

	if (fgets(line, sizeof(line), attr_file) != NULL) {
		size_t len = strlen(line);

		/* fgets() reads in line, including newline character. */
		if (line[len - 1] != '\n') {
			G_LOG(ERR, "Line buffer too short to read in %s from %s\n",
				attr, path);
			ret = -1;
			goto close;
		}

		/* Remove newline. */
		line[len - 1] = '\0';
		len--;

		if (len > val_len - 1) {
			G_LOG(ERR, "Found attribute in %s but value buffer is too short to read in its value (%s)\n",
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
		G_LOG(ERR, "Unable to fetch srcversion of %s.ko file specified in config\n",
			KNI_MODULE_NAME);
		return false;
	}

	ret = get_loaded_kmod_attr("srcversion",
		loaded_kmod_srcver, sizeof(loaded_kmod_srcver));
	if (ret < 0) {
		G_LOG(ERR, "Unable to fetch srcversion of %s module already loaded\n",
			KNI_MODULE_NAME);
		return false;
	}

	if (strcmp(kmod_srcver, loaded_kmod_srcver) == 0)
		return true;

	G_LOG(ERR, "srcversion of loaded %s module (%s) does not match srcversion of %s.ko file specified in config (%s)\n",
		KNI_MODULE_NAME, loaded_kmod_srcver,
		KNI_MODULE_NAME, kmod_srcver);
	return false;
}

static int
find_kni_kmod_path(char *path, size_t path_len, const char *alias)
{
	struct kmod_ctx *ctx;
	char dirname[PATH_MAX];
	struct utsname u;
	struct kmod_list *l, *filtered, *list = NULL;
	int ret;

	/* Get kernel name and build module path. */
	if (uname(&u) < 0) {
		G_LOG(ERR, "uname: %s\n", strerror(errno));
		return -1;
	}
	ret = snprintf(dirname, sizeof(dirname),
		"/lib/modules/%s", u.release);
	if (ret <= 0 || ret >= (int)sizeof(dirname)) {
		G_LOG(ERR, "Could not build path name for release %s and module %s\n",
			u.release, alias);
		return -1;
	}

	/*
	 * Create kmod library context using default configuration.
	 * The context that's created has an inital refcount of 1.
	 */
	ctx = kmod_new(dirname, NULL);
	if (ctx == NULL) {
		G_LOG(ERR, "kmod_new failed\n");
		return -1;
	}

	/*
	 * Create a list of kernel modules that match the alias.
	 * The initial refcount of the list is 1 and must be released.
	 */
	ret = kmod_module_new_from_lookup(ctx, alias, &list);
	if (ret < 0) {
		G_LOG(ERR, "Failed to lookup module alias %s\n", alias);
		ret = -1;
		goto put_ctx;
	}
	if (list == NULL) {
		G_LOG(ERR, "Module %s not found\n", alias);
		ret = -1;
		goto put_ctx;
	}

	/* Filter out builtin modules from the list.*/
	ret = kmod_module_apply_filter(ctx, KMOD_FILTER_BUILTIN,
		list, &filtered);

	/* Filtered list is now stored in @filtered, so release @list. */
	kmod_module_unref_list(list);

	if (ret < 0) {
		G_LOG(ERR, "Failed to filter kernel module list to find %s\n",
			alias);
		ret = -1;
		goto put_ctx;
	}
	if (filtered == NULL) {
		G_LOG(ERR, "Module %s not found\n", alias);
		ret = -1;
		goto put_ctx;
	}

	kmod_list_foreach(l, filtered) {
		struct kmod_module *mod = kmod_module_get_module(l);
		const char *kmod_name = kmod_module_get_name(mod);
		const char *kmod_path;

		/* Not the module we're looking for. */
		if (strcmp(kmod_name, alias) != 0) {
			kmod_module_unref(mod);
			continue;
		}

		kmod_path = kmod_module_get_path(mod);
		if (strlen(kmod_path) > path_len - 1) {
			G_LOG(ERR, "Found kernel module path (%s) but buffer is too short to hold it\n",
				kmod_path);
			ret = -1;
		} else {
			strcpy(path, kmod_path);
			ret = 0;
		}

		kmod_module_unref(mod);
		break;
	}

	kmod_module_unref_list(filtered);
put_ctx:
	kmod_unref(ctx);
	return ret;
}

int
init_kni(const char *kni_kmod_path, unsigned int num_kni)
{
	char path[PATH_MAX];
	void *file;
	unsigned long len;
	int ret;

	if (kni_kmod_path == NULL) {
		ret = find_kni_kmod_path(path, sizeof(path), KNI_MODULE_NAME);
		if (ret < 0) {
			G_LOG(ERR, "KNI kernel module path not found; must be set in CPS configuration file\n");
			return ret;
		}
		kni_kmod_path = path;
	}

	file = grab_file(kni_kmod_path, &len);
	if (file == NULL) {
		G_LOG(ERR, "%s: can't read '%s'\n", __func__, kni_kmod_path);
		return -1;
	}

	ret = init_module(file, len, "");
	if (ret < 0) {
		if (errno == EEXIST) {
			G_LOG(NOTICE, "%s: %s already inserted\n",
				__func__, kni_kmod_path);

			if (loaded_kmod_matches_file(file, len)) {
				ret = 0;
				goto success;
			}
		} else {
			G_LOG(ERR, "%s: error inserting '%s': %d %s\n",
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
		G_LOG(ERR, "Can't open %s: %s\n", PROC_MODULES_FILENAME,
			strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), module_list) != NULL) {
		unsigned long size, refs;
		int scanned;

		found_mods = true;

		if (strchr(line, '\n') == NULL) {
			G_LOG(ERR, "Line too long while reading loaded modules file %s\n",
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
				G_LOG(ERR, "Unknown format in %s: %s\n",
					PROC_MODULES_FILENAME, line);
			else
				G_LOG(ERR,
					"Kernel doesn't support unloading\n");
			ret = -1;
			goto out;
		}

		if (strcmp(name, modname) != 0)
			continue;

		if (refs != 0) {
			G_LOG(ERR, "Module %s is in use\n", modname);
			ret = -1;
		}

		goto out;
	}

	if (found_mods)
		G_LOG(ERR, "Module %s does not exist in %s\n", modname,
			PROC_MODULES_FILENAME);
	else
		G_LOG(ERR, "fgets: error in reading %s\n",
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
		G_LOG(ERR, "Error removing %s: %s\n", name, strerror(errno));
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
		G_LOG(ERR, "%s: allocation of mailbox message failed\n",
			__func__);
		return;
	}

	req->ty = CPS_REQ_ARP;
	req->u.arp.ip = map->addr.ip.v4.s_addr;
	rte_memcpy(&req->u.arp.ha, &map->ha, sizeof(req->u.arp.ha));
	req->u.arp.iface = arg;

	ret = mb_send_entry(&cps_conf->mailbox, req);
	if (ret < 0) {
		G_LOG(ERR, "%s: failed to enqueue message to mailbox\n",
			__func__);
		return;
	}
}

void
kni_process_arp(struct cps_config *cps_conf, struct gatekeeper_if *iface,
	struct rte_mbuf *buf, const struct rte_ether_hdr *eth_hdr)
{
	int ret;
	struct rte_arp_hdr *arp_hdr;
	uint16_t pkt_len = rte_pktmbuf_data_len(buf);
	struct arp_request *arp_req = NULL;
	struct arp_request *entry;

	if (unlikely(!arp_enabled(cps_conf->lls))) {
		G_LOG(NOTICE, "KNI for %s iface received ARP packet, but the interface is not configured for ARP\n",
			iface->name);
		goto out;
	}

	if (unlikely(pkt_len < sizeof(*eth_hdr) + sizeof(*arp_hdr))) {
		G_LOG(ERR, "KNI received ARP packet of size %hu bytes, but it should be at least %zu bytes\n",
			pkt_len, sizeof(*eth_hdr) + sizeof(*arp_hdr));
		goto out;
	}

	arp_hdr = rte_pktmbuf_mtod_offset(buf, struct rte_arp_hdr *,
		sizeof(*eth_hdr));

	/* If it's a Gratuitous ARP or reply, then no action is needed. */
	if (unlikely(rte_be_to_cpu_16(arp_hdr->arp_opcode) !=
			RTE_ARP_OP_REQUEST || is_garp_pkt(arp_hdr)))
		goto out;

	list_for_each_entry(entry, &cps_conf->arp_requests, list) {
		/* There's already a resolution request for this address. */
		if (arp_hdr->arp_data.arp_tip == entry->addr)
			goto out;
	}

	ret = rte_mempool_get(cps_conf->arp_mp, (void **)&arp_req);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "Failed to get a new entry from the ARP request mempool - %s\n",
			strerror(-ret));
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
		G_LOG(ERR, "%s: allocation of mailbox message failed\n",
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
		G_LOG(ERR, "%s: failed to enqueue message to mailbox\n",
			__func__);
		return;
	}
}

void
kni_process_nd(struct cps_config *cps_conf, struct gatekeeper_if *iface,
	struct rte_mbuf *buf, const struct rte_ether_hdr *eth_hdr,
	uint16_t pkt_len)
{
	int ret;
	struct icmpv6_hdr *icmpv6_hdr;
	struct nd_neigh_msg *nd_msg;
	struct nd_request *nd_req = NULL;
	struct nd_request *entry;

	if (unlikely(!nd_enabled(cps_conf->lls))) {
		G_LOG(NOTICE, "KNI for %s iface received ND packet, but the interface is not configured for ND\n",
			iface->name);
		goto out;
	}

	if (pkt_len < ND_NEIGH_PKT_MIN_LEN(sizeof(*eth_hdr))) {
		G_LOG(NOTICE, "ND packet received is %"PRIx16" bytes but should be at least %lu bytes\n",
			pkt_len, ND_NEIGH_PKT_MIN_LEN(sizeof(*eth_hdr)));
		goto out;
	}

	icmpv6_hdr = rte_pktmbuf_mtod_offset(buf, struct icmpv6_hdr *,
		sizeof(*eth_hdr) + sizeof(struct rte_ipv6_hdr));
	if (icmpv6_hdr->type == ND_NEIGHBOR_ADVERTISEMENT_TYPE &&
			icmpv6_hdr->code == ND_NEIGHBOR_ADVERTISEMENT_CODE) {
		G_LOG(NOTICE, "ND Advertisement packet received from KNI attached to %s iface\n",
			iface->name);
		goto out;
	}

	nd_msg = (struct nd_neigh_msg *)&icmpv6_hdr[1];

	list_for_each_entry(entry, &cps_conf->nd_requests, list) {
		/* There's already a resolution request for this address. */
		if (ipv6_addrs_equal(nd_msg->target, entry->addr))
			goto out;
	}

	ret = rte_mempool_get(cps_conf->nd_mp, (void **)&nd_req);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "Failed to get a new entry from the ND request mempool - %s\n",
			strerror(-ret));
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
