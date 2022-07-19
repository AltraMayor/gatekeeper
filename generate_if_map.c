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

#include <stdio.h>
#include <string.h>
#include <argp.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h> 
#include <linux/sockios.h>

/* Argp's global variables. */
const char *argp_program_version = "generate-if-map 1.0";

/* Arguments. */
static char adoc[] = "<IF_MAP_LUA>";

static char doc[] = "generate-if-map -- generate the mapping "
	"network interface device name to its bus information";


static struct argp_option options[] = {
	{"gatekeeper-if-map", 'o', "FILE", 0,
		"Output the mapping to a Lua FILE", 1},
	{ 0 }
};


struct args {
	char *filename;
};

static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
	struct args *args = state->input;

	switch (key) {
	case 'o':
		args->filename = arg;
		break;

	case ARGP_KEY_INIT:
		args->filename = NULL;
		break;

	case ARGP_KEY_ARG:
		if (args->filename)
			argp_error(state,
				"Wrong number of arguments; only one is allowed");
		args->filename = arg;
		break;

	case ARGP_KEY_END:
		if (!args->filename)
			argp_error(state,
				"The mapping Lua file was not specified");
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = {options, parse_opt, adoc, doc, NULL, NULL, NULL};

int
main(int argc, char **argv)
{
	FILE *f;
	struct ifaddrs *addrs, *iter;
	int sock;
	int ret;
	struct args args = {
		/* Defaults. */
		.filename = "./lua/if_map.lua",
	};

	/* Read parameters. */
	argp_parse(&argp, argc, argv, 0, NULL, &args);

	f = fopen(args.filename, "w");
	if (f == NULL) {
		perror("fopen");
		return -1;
	}

	ret = getifaddrs(&addrs);
	if (ret == -1) {
		perror("getifaddrs");
		goto file;
	}

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("socket");
		goto addrs;
	}

	fprintf(f, "return {\n");

	iter = addrs;
	while (iter != NULL) {
		struct ifreq ifr;
		struct ethtool_cmd cmd;
		struct ethtool_drvinfo drvinfo;

		/*
		 * Use AF_PACKET to only get each interface once,
		 * and skip the loopback interface.
		 */
		if (iter->ifa_addr == NULL ||
				iter->ifa_addr->sa_family != AF_PACKET ||
				strcmp(iter->ifa_name, "lo") == 0)
			goto next;

		memset(&ifr, 0, sizeof(ifr));
		memset(&cmd, 0, sizeof(cmd));
		memset(&drvinfo, 0, sizeof(drvinfo));
		strcpy(ifr.ifr_name, iter->ifa_name);

		ifr.ifr_data = (void *)&drvinfo;
		drvinfo.cmd = ETHTOOL_GDRVINFO;

		if (ioctl(sock, SIOCETHTOOL, &ifr) < 0) {
			perror("ioctl");
			goto next;
		}

		fprintf(f, "\t[\"%s\"] = \"%s\",\n", iter->ifa_name,
			drvinfo.bus_info);
next:
		iter = iter->ifa_next;
	}

	fprintf(f, "}\n");

	close(sock);
addrs:
	freeifaddrs(addrs);
file:
	fclose(f);
	return ret;
}
