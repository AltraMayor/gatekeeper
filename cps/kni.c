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
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_kni.h>
#include <rte_malloc.h>

#include "gatekeeper_cps.h"
#include "gatekeeper_main.h"
#include "kni.h"

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
