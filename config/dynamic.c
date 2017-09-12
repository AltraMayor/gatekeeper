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

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <lualib.h>
#include <lauxlib.h>

#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_malloc.h>

#include "gatekeeper_net.h"
#include "gatekeeper_main.h"
#include "gatekeeper_config.h"
#include "gatekeeper_launch.h"

/*
 * The cast "(uint16_t)" is needed because of
 * the strict compilation check of DPDK,
 * without uint16_t, it pops an error message
 * "error: large integer implicitly truncated to
 * unsigned type [-Werror=overflow]."
 */
static const uint16_t MSG_MAX_LEN = (uint16_t)~0U;

static struct dynamic_config config;

/*
 * Return values:
 * 	0: Write @nbytes successfully.
 * 	-1: Connection closed by the client.
 */
static int
write_nbytes(int conn_fd, const char *msg_buff, int nbytes)
{
	int send_size;
	int tot_size = 0;

	if (nbytes == 0)
		return 0;

	while ((send_size = write(conn_fd, msg_buff + tot_size,
			nbytes - tot_size)) > 0) {
		tot_size += send_size;
		if (tot_size >= nbytes)
			break;
	}

	/* The connection with the client is closed. */
	if (send_size == 0) {
		RTE_LOG(WARNING, GATEKEEPER,
			"dyn_cfg: Client disconnected\n");
		return -1;
	}

	if (send_size < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"dyn_cfg: Failed to write data to the socket connection - (%s)\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

static int
reply_client_message(int conn_fd, const char *reply_msg, uint16_t reply_len)
{
	int ret;
	uint16_t nlen = htons(reply_len);

	/* The first two bytes: the length of the message in network order. */
	ret = write_nbytes(conn_fd, (char *)&nlen, sizeof(nlen));
	if (ret != 0)
		return -1;

	/* Sending the message. */
	ret = write_nbytes(conn_fd, reply_msg, reply_len);
	if (ret != 0)
		return -1;

	return 0;
}

static int
process_client_message(int conn_fd,
	const char *msg, int msg_len, lua_State *lua_state)
{
	/*
	 * TODO Implement the functionalities to process the clients' request.
	 *
	 * Gatekeeper and Grantor: Listing the ARP and ND table.
	 * This is important for network diagnosis.
	 *
	 * Grantor: Updating the policy GTs run.
	 */

	int ret;
	size_t reply_len;
	const char *reply_msg;
	const char *CLIENT_EMPTY_ERROR =
		"Dynamic configuration cannot process the request: the request is empty.";
	const char *CLIENT_PROC_ERROR =
		"Dynamic configuration: the reply was NULL.";

	if (msg_len == 0) {
		RTE_LOG(WARNING, LUA,
			"dyn_cfg: the received message is an empty string\n");
		return reply_client_message(conn_fd,
			CLIENT_EMPTY_ERROR, strlen(CLIENT_EMPTY_ERROR));
	}

	/* Load the client's Lua chunk, and run it. */
	ret = luaL_loadbuffer(lua_state, msg, msg_len, "message")
		|| lua_pcall(lua_state, 0, 1, 0);
	if (ret != 0) {
		reply_msg = luaL_checklstring(lua_state, -1, &reply_len);

		if (reply_len > MSG_MAX_LEN) {
			char truncated_reply_msg[MSG_MAX_LEN];
			strncpy(truncated_reply_msg, reply_msg, MSG_MAX_LEN);
			truncated_reply_msg[MSG_MAX_LEN - 1] = '\0';

			RTE_LOG(ERR, LUA, "dyn_cfg: %s!\n", truncated_reply_msg);

			RTE_LOG(WARNING, LUA,
				"dyn_cfg: The error message length (%lu) exceeds the limit!\n",
				reply_len);

			reply_len = MSG_MAX_LEN;
		} else
			RTE_LOG(ERR, LUA, "dyn_cfg: %s!\n", reply_msg);

		return reply_client_message(conn_fd, reply_msg, reply_len);
	}

	reply_msg = luaL_checklstring(lua_state, -1, &reply_len);
	if (reply_msg == NULL) {
		RTE_LOG(ERR, LUA,
			"dyn_cfg: The client request script returns a NULL string!\n");
		return reply_client_message(conn_fd,
			CLIENT_PROC_ERROR, strlen(CLIENT_PROC_ERROR));
	}

	if (reply_len > MSG_MAX_LEN) {
		RTE_LOG(WARNING, LUA,
			"dyn_cfg: The reply message length (%lu) exceeds the limit!\n",
			reply_len);
		reply_len = MSG_MAX_LEN;
	}

	return reply_client_message(conn_fd, reply_msg, reply_len);
}

/*
 * Return values:
 * 	0: Read @nbytes successfully.
 * 	-1: The client closed the connection or an error occurred.
 */
static int
read_nbytes(int conn_fd, char *msg_buff, int nbytes)
{
	int recv_size;
	int tot_size = 0;

	while ((recv_size = read(conn_fd, msg_buff + tot_size,
			nbytes - tot_size)) > 0) {
		tot_size += recv_size;
		if (tot_size >= nbytes)
			break;
	}

	/* The connection with the client is closed. */
	if (recv_size == 0) {
		RTE_LOG(WARNING, GATEKEEPER,
			"dyn_cfg: Client disconnected\n");
		return -1;
	}

	if (recv_size < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"dyn_cfg: Failed to read data from the socket connection - (%s)\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

/*
 * Return values:
 * 	-1: Error happens.
 * 	0: Command successfully processed, may need to process further commands.
 */
static int
process_single_cmd(int conn_fd, lua_State *lua_state)
{
	int ret;
	uint16_t msg_len;
	char msg_buff[MSG_MAX_LEN];

	/*
	 * The protocol should be rather simple: two-byte,
	 * unsigned integer in network order signal the size,
	 * in bytes, of the message that follows that
	 * first two bytes.
	 */
	ret = read_nbytes(conn_fd, (char *)&msg_len, 2);
	if (ret != 0)
		return -1;

	msg_len = ntohs(msg_len);
	RTE_VERIFY(msg_len <= MSG_MAX_LEN);

	ret = read_nbytes(conn_fd, msg_buff, msg_len);
	if (ret != 0)
		return -1;

	ret = process_client_message(
		conn_fd, msg_buff, msg_len, lua_state);
	if (ret < 0)
		return -1;

	return 0;
}

static void
cleanup_dy(struct dynamic_config *dy_conf)
{
	int ret;

	if (dy_conf->gk != NULL) {
		gk_conf_put(dy_conf->gk);
		dy_conf->gk = NULL;
	}

	if (dy_conf->sock_fd != -1) {
		ret = close(dy_conf->sock_fd);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER,
				"dyn_cfg: Failed to close the server socket - (%s)\n",
				strerror(errno));
		}
		dy_conf->sock_fd = -1;
	}

	if (dy_conf->server_path != NULL) {
		ret = unlink(dy_conf->server_path);
		if (ret != 0) {
			RTE_LOG(WARNING, GATEKEEPER,
				"dyn_cfg: Failed to unlink(%s) - (%s)\n",
				dy_conf->server_path, strerror(errno));
		}

		rte_free(dy_conf->server_path);
		dy_conf->server_path = NULL;
	}
}

static int 
setup_dy_lua(lua_State *lua_state, struct dynamic_config *dy_conf)
{
	int ret;
	char lua_entry_path[128];

	ret = snprintf(lua_entry_path, sizeof(lua_entry_path), "%s/%s",
		dy_conf->lua_dy_base_dir, dy_conf->dynamic_config_file);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(lua_entry_path));

	luaL_openlibs(lua_state);
	set_lua_path(lua_state, dy_conf->lua_dy_base_dir);
	ret = luaL_loadfile(lua_state, lua_entry_path);
	if (ret != 0) {
		RTE_LOG(ERR, LUA,
			"dyn_cfg: %s!\n", lua_tostring(lua_state, -1));
		return -1;
	}

	ret = lua_pcall(lua_state, 0, 0, 0);
	if (ret != 0) {
		RTE_LOG(ERR, LUA,
			"dyn_cfg: %s!\n", lua_tostring(lua_state, -1));
		return -1;
	}

	return 0;
}

static void
handle_client(int server_socket_fd, struct dynamic_config *dy_conf)
{
	int ret;
	int conn_fd;
	socklen_t len;
	int rcv_buff_size;
	struct sockaddr_un client_addr;

	/* The lua state used to handle the dynamic configuration files. */
	lua_State *lua_state;

	len = sizeof(client_addr);
	conn_fd = accept(server_socket_fd,
		(struct sockaddr *)&client_addr, &len);
	if (conn_fd < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"dyn_cfg: Failed to accept a new connection - (%s)\n",
			strerror(errno));
		return;
	}

	if (unlikely(client_addr.sun_family != AF_UNIX)) {
		RTE_LOG(WARNING, GATEKEEPER,
			"Unexpected condition: unknown client type %d at %s\n",
			client_addr.sun_family, __func__);
		goto close_fd;
	}

	/*
	 * The request must be received under a specified timeout,
	 * or the request is aborted.
	 */
	ret = setsockopt(conn_fd, SOL_SOCKET, SO_RCVTIMEO,
		(const char*)&dy_conf->rcv_time_out, sizeof(struct timeval));
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"dyn_cfg: Failed to call setsockopt(SO_RCVTIMEO) - (%s)\n",
			strerror(errno));
		goto close_fd;
	}

	rcv_buff_size = MSG_MAX_LEN;
	ret = setsockopt(conn_fd, SOL_SOCKET,
		SO_RCVBUF, &rcv_buff_size, sizeof(rcv_buff_size));
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"dyn_cfg: Failed to call setsockopt(SO_RCVBUF) with size = %d - (%s)\n",
			rcv_buff_size, strerror(errno));
		goto close_fd;
	}

	lua_state = luaL_newstate();
	if (lua_state == NULL) {
		RTE_LOG(ERR, LUA,
			"dyn_cfg: failed to create new Lua state!\n");
		goto close_fd;
	}

	/* Set up the Lua state while there is a connection. */
	ret = setup_dy_lua(lua_state, dy_conf);
	if (ret < 0) {
		RTE_LOG(ERR, LUA,
			"dyn_cfg: Failed to set up the lua state\n");
		goto close_lua;
	}

	while (1) {
		ret = process_single_cmd(conn_fd, lua_state);
		if (ret != 0)
			break;
	}

close_lua:
	lua_close(lua_state);

close_fd:
	ret = close(conn_fd);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"dyn_cfg: Failed to close the connection socket - (%s)\n",
			strerror(errno));
	}
}

static int
dyn_cfg_proc(void *arg)
{
	int ret = 0;
	struct dynamic_config *dy_conf = arg;
	uint32_t lcore = dy_conf->lcore_id;

	RTE_LOG(NOTICE, GATEKEEPER,
		"dyn_cfg: the Dynamic Config block is running at lcore = %u\n", lcore);

	while (likely(!exiting)) {
		fd_set fds;
		struct timeval stv;
 
		FD_ZERO(&fds);
		FD_SET(dy_conf->sock_fd, &fds);
 
		/*
		 * 10000 usecs' timeout for the select() function.
		 * This parameter can prevent the select() function
		 * from blocking forever. So, the whole program can
		 * exit when receiving a quitting signal.
		 */
		stv.tv_sec = 0;
		stv.tv_usec = 10000;

		ret = select(dy_conf->sock_fd + 1, &fds, NULL, NULL, &stv);
		if (ret < 0 && errno != EINTR) {
			RTE_LOG(ERR, GATEKEEPER,
				"dyn_cfg: Failed to call the select() function - (%s)\n",
				strerror(errno));
			break;
		} else if (likely(ret <= 0)) {
			if (unlikely(ret < 0))
				RTE_VERIFY(errno == EINTR);
			continue;
		}

		/*
		 * The config component accepts only one connection at a time.
		 */
		RTE_VERIFY(FD_ISSET(dy_conf->sock_fd, &fds));
		handle_client(dy_conf->sock_fd, dy_conf);
	}

	RTE_LOG(NOTICE, GATEKEEPER,
		"dyn_cfg: the Dynamic Config block at lcore = %u is exiting\n", lcore);

	cleanup_dy(dy_conf);

	return ret;
}

struct dynamic_config *
get_dy_conf(void)
{
	return &config;
}

void
set_dyc_timeout(unsigned int sec,
	unsigned int usec, struct dynamic_config *dy_conf)
{
	dy_conf->rcv_time_out.tv_sec = sec;
	dy_conf->rcv_time_out.tv_usec = usec;
}

int
run_dynamic_config(struct gk_config *gk_conf,
	const char *server_path, const char *lua_dy_base_dir,
	const char *dynamic_config_file, struct dynamic_config *dy_conf)
{
	int ret;
	struct sockaddr_un server_addr;

	/*
	 * When the dynamic configuration is run for Gatekeeper,
	 * the gt_conf should be NULL.
	 * When the dynamic configuration is run for Grantor,
	 * the gk_conf should be NULL.
	 * The code works fine with both being NULL as well.
	 * This way, not only will the dynamic config block work for
	 * the Grantor case, it could work for unforeseen cases as well.
	 */
	if (server_path == NULL || lua_dy_base_dir == NULL ||
			dynamic_config_file == NULL || dy_conf == NULL) {
		ret = -1;
		goto out;
	}

	dy_conf->sock_fd = -1;

	dy_conf->server_path = rte_malloc(
		"server_path", strlen(server_path) + 1, 0);
	if (dy_conf->server_path == NULL) {
		ret = -1;
		goto out;
	}
	strcpy(dy_conf->server_path, server_path);

	/*
	 * Remove any old socket and create an unnamed socket for the server.
	 */
	ret = unlink(dy_conf->server_path);
	if (ret != 0 && errno != ENOENT) {
		RTE_LOG(ERR, GATEKEEPER,
			"dyn_cfg: Failed to unlink(%s) - (%s)\n",
			dy_conf->server_path, strerror(errno));
		ret = -1;
		goto free_server_path;
	}

	dy_conf->lua_dy_base_dir = rte_malloc(
		"lua_dy_base_dir", strlen(lua_dy_base_dir) + 1, 0);
	if (dy_conf->lua_dy_base_dir == NULL) {
		ret = -1;
		goto free_server_path;
	}
	strcpy(dy_conf->lua_dy_base_dir, lua_dy_base_dir);

	dy_conf->dynamic_config_file = rte_malloc(
		"dynamic_config_file", strlen(dynamic_config_file) + 1, 0);
	if (dy_conf->dynamic_config_file == NULL) {
		ret = -1;
		goto free_dy_lua_base_dir;
	}
	strcpy(dy_conf->dynamic_config_file, dynamic_config_file);

	/* Init the server socket. */
    	dy_conf->sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (dy_conf->sock_fd < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"dyn_cfg: Failed to initialize the server socket - (%s)\n",
			strerror(errno));
		ret = -1;
		goto free_dynamic_config_file;
	}

	/* Name the socket. */
    	memset(&server_addr, 0, sizeof(server_addr));
    	server_addr.sun_family = AF_UNIX;

	if (sizeof(server_addr.sun_path) <= strlen(dy_conf->server_path)) {
		RTE_LOG(ERR, GATEKEEPER,
			"dyn_cfg: the server path (%s) exceeds the length limit %lu\n",
			dy_conf->server_path, sizeof(server_addr.sun_path));
		ret = -1;
		goto free_sock;
	}

    	strcpy(server_addr.sun_path, dy_conf->server_path);

    	ret = bind(dy_conf->sock_fd,
		(struct sockaddr *)&server_addr, sizeof(server_addr));
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"dyn_cfg: Failed to bind the server socket - (%s)\n",
			strerror(errno));
		ret = -1;
		goto free_sock;
	}

	/*
	 * The Dynamic config component listens to a Unix socket
	 * for request from the local host.
	 */
    	ret = listen(dy_conf->sock_fd, 10);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"dyn_cfg: Failed to listen on the server socket - (%s)\n",
			strerror(errno));
		ret = -1;
		goto free_sock;
	}

	/*
	 * TODO Add support for the dynamic configuration running as Grantor.
	 */
	if (gk_conf != NULL)
		gk_conf_hold(gk_conf);
	dy_conf->gk = gk_conf;

	ret = launch_at_stage3("dynamic_conf",
		dyn_cfg_proc, dy_conf, dy_conf->lcore_id);
	if (ret < 0)
		goto put_gk_config;

	return 0;

put_gk_config:
	dy_conf->gk = NULL;
	if (gk_conf != NULL)
		gk_conf_put(gk_conf);
free_sock:
	close(dy_conf->sock_fd);
	dy_conf->sock_fd = -1;

free_dynamic_config_file:
	rte_free(dy_conf->dynamic_config_file);
	dy_conf->dynamic_config_file = NULL;

free_dy_lua_base_dir:
	rte_free(dy_conf->lua_dy_base_dir);
	dy_conf->lua_dy_base_dir = NULL;

free_server_path:
	rte_free(dy_conf->server_path);
	dy_conf->server_path = NULL;

out:
	return ret;
}
