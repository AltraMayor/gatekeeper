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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <error.h>
#include <argp.h>
#include <assert.h>

static const uint16_t MSG_MAX_LEN = (uint16_t)~0U;

/* Argp's global variables. */
const char *argp_program_version =
	"Gatekeeper dynamic configuration client 1.0";

/* Arguments. */
static char adoc[] = "<PATH>";

static char doc[] = "Gatekeeper Client -- configure Gatekeeper via "
	"the dynamic configuration functional block";

static struct argp_option options[] = {
	{"server-path",		's',	"FILE",		0,
		"Path to Gatekeeper/Grantor's UNIX socket",	1},
	{"conn-timeout",	't',	"TIMEOUT",	0,
		"UNIX socket connect timeout, in seconds",	1},
	{ 0 }
};

struct args {
	const char *server_path;
	const char *lua_script_path;
	unsigned int connect_timeout;
};

static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
	struct args *args = state->input;

	switch (key) {
	case 's':
		args->server_path = arg;
		break;

	case 't': {
		unsigned long timeout;

		errno = 0;
		timeout = strtoul(arg, NULL, 10);
		if (errno != 0)
			argp_failure(state, 1, errno, "Invalid connect timeout");
		if (timeout > UINT_MAX)
			argp_failure(state, 1, ERANGE, "Invalid connect timeout");
		args->connect_timeout = timeout;
		break;
	}

	case ARGP_KEY_INIT:
		args->lua_script_path = NULL;
		break;

	case ARGP_KEY_ARG:
		if (args->lua_script_path) {
			argp_error(state,
				"Wrong number of arguments; only one is allowed");
		}
		args->lua_script_path = arg;
		break;

	case ARGP_KEY_END:
		if (!args->lua_script_path) {
			argp_error(state,
				"The lua script path was not specified");
		}
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = {options, parse_opt, adoc, doc, NULL, NULL, NULL};

static int
load_file_to_buffer(const char *file_name, char *buffer, int n)
{
	int ret;
	FILE *fp = fopen(file_name, "r");
	if (fp == NULL) {
		fprintf(stderr, "Error: Failed to open file %s - %s\n",
			file_name, strerror(errno));
		ret = -1;
		goto out;
	}

	/*
	 * Return value equals the number of bytes transferred
	 * only when size (i.e., second parameter) is 1.
	 */
	ret = fread(buffer, 1, n, fp);
	if (ferror(fp)) {
		fprintf(stderr, "Error: %s\n", strerror(errno));
		ret = -1;
	} else if (!feof(fp)) {
		assert(ret == n);
		fprintf(stderr, "Error: Failed to read the whole file %s (file length exceeds the maximum message size - %d)\n",
			file_name, n);
		ret = -1;
	}

	fclose(fp);
out:
	return ret;
}

static int
write_all(int conn_fd, const char *msg_buff, int nbytes)
{
	int send_size;
	int tot_size = 0;

	if (nbytes <= 0)
		return 0;

	while ((send_size = write(conn_fd, msg_buff + tot_size,
			nbytes - tot_size)) > 0) {
		tot_size += send_size;
		if (tot_size >= nbytes)
			break;
	}

	/* The connection with the server is closed. */
	if (send_size == 0) {
		fprintf(stderr, "Server disconnected\n");
		return -1;
	}

	if (send_size < 0) {
		fprintf(stderr, "Failed to write data to the socket connection - (%s)\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

static int
read_all(int conn_fd, char *msg_buff, int nbytes)
{
	int recv_size;
	int tot_size = 0;

	if (nbytes <= 0)
		return 0;

	while ((recv_size = read(conn_fd, msg_buff + tot_size,
			nbytes - tot_size)) > 0) {
		tot_size += recv_size;
		if (tot_size >= nbytes)
			break;
	}

	/* The connection with the server is closed. */
	if (recv_size == 0) {
		fprintf(stderr, "Server disconnected\n");
		return -1;
	}

	if (recv_size < 0) {
		fprintf(stderr, "Failed to read data from the socket connection - (%s)\n",
			strerror(errno));
		return -1;
	}

	return tot_size;
}

int
connect_wait(int sock_fd, const struct sockaddr *addr, socklen_t addrlen,
	unsigned int timeout)
{
	unsigned int remain = timeout;

	for (;;) {
		if (connect(sock_fd, addr, addrlen) == 0)
			return 0;
		switch (errno) {
			/* Retry in case of these expected errors:
			 *   1) Gatekeeper has not yet created the dynamic configuration
			 *      socket;
			 *   2) Gatekeeper has created the socket but its permissions
			 *      have not yet been changed to allow access to the
			 *      unprivileged user (can only happpen if gkctl itself is
			 *      running as the unprivileged user);
			 *   3) Gatekeeper is not yet listening on the socket.
			 */
			case ENOENT:
			case EPERM:
			case ECONNREFUSED:
				if (remain == 0)
					return -1;
				sleep(1);
				remain--;
				break;
			default:
				return -1;
		}
	}
}

int
main(int argc, char *argv[])
{
	int ret;
	int sock_fd;
	char send_buff[MSG_MAX_LEN + sizeof(uint16_t)];
	char recv_buff[MSG_MAX_LEN + 1];
	size_t len;
	size_t total_file_len;
	struct sockaddr_un serv_addr;

	struct args args = {
		/* Defaults. */
		.server_path = "/var/run/gatekeeper/dyn_cfg.socket",
		.connect_timeout = 0,
	};

	/* Read parameters. */
	argp_parse(&argp, argc, argv, 0, NULL, &args);

	if (sizeof(serv_addr.sun_path) <= strlen(args.server_path)) {
		fprintf(stderr, "Error: passing a too long server path (i.e., > %lu) - %s\n",
			sizeof(serv_addr.sun_path), args.server_path);
		ret = -1;
		goto out;
	}
	serv_addr.sun_family = AF_UNIX;
	strcpy(serv_addr.sun_path, args.server_path);

	ret = load_file_to_buffer(args.lua_script_path,
		send_buff + sizeof(uint16_t), MSG_MAX_LEN);
	if (ret < 0) {
		ret = -1;
		goto out;
	} else if (ret == 0) {
		fprintf(stderr, "Error: the file %s is empty\n",
			args.lua_script_path);
		goto out;
	}
	total_file_len = ret;
	*(uint16_t *)send_buff = htons(ret);

	if ((sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("Error: Could not create socket");
		ret = -1;
		goto out;
	}

	if (connect_wait(sock_fd, (struct sockaddr *)&serv_addr,
			sizeof(serv_addr), args.connect_timeout) < 0) {
		perror("Error: Connect failed");
		ret = -1;
		goto close_sock;
	}

	ret = write_all(sock_fd, send_buff, total_file_len + sizeof(uint16_t));
	if (ret != 0) {
		fprintf(stderr, "Failed to send message\n");
		ret = -1;
		goto close_sock;
	}

	ret = read_all(sock_fd, recv_buff, sizeof(uint16_t));
	if (ret != sizeof(uint16_t)) {
		fprintf(stderr, "Failed to receive message length\n");
		ret = -1;
		goto close_sock;
	}

	len = ntohs(*(uint16_t *)recv_buff);
	if (len == 0) {
		fprintf(stderr, "Received a message with no body\n");
		ret = -1;
		goto close_sock;
	}

	ret = read_all(sock_fd, recv_buff, len);
	if (ret != (int)len) {
		fprintf(stderr, "Failed to receive message\n");
		ret = -1;
		goto close_sock;
	}

	if (recv_buff[ret - 1] != '\0')
		recv_buff[ret] = '\0';
	printf("%s\n", recv_buff);
	ret = 0;

close_sock:
	close(sock_fd);
out:
	return ret;
}
