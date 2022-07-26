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

/* For gettid(). */
#define _GNU_SOURCE

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <lualib.h>
#include <lauxlib.h>

#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_malloc.h>

#include "gatekeeper_net.h"
#include "gatekeeper_lls.h"
#include "gatekeeper_main.h"
#include "gatekeeper_config.h"
#include "gatekeeper_launch.h"
#include "gatekeeper_log_ratelimit.h"

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

	/*
	 * The connection with the client is closed.
	 * This is unexpected, since the client closed
	 * the connection before getting a response.
	 */
	if (send_size == 0) {
		G_LOG(WARNING, "Client disconnected\n");
		return -1;
	}

	if (send_size < 0) {
		G_LOG(ERR,
			"Failed to write data to the socket connection - (%s)\n",
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
	int ret;
	size_t reply_len;
	const char *reply_msg;
	const char *CLIENT_EMPTY_ERROR =
		"Dynamic configuration cannot process the request: the request is empty.";
	const char *CLIENT_PROC_ERROR =
		"Dynamic configuration: the reply was NULL.";

	if (msg_len == 0) {
		G_LOG(WARNING, "The received message is an empty string\n");
		return reply_client_message(conn_fd,
			CLIENT_EMPTY_ERROR, strlen(CLIENT_EMPTY_ERROR));
	}

	/* Load the client's Lua chunk, and run it. */
	ret = luaL_loadbuffer(lua_state, msg, msg_len, "message")
		|| lua_pcall(lua_state, 0, 1, 0);

	reply_msg = lua_tolstring(lua_state, -1, &reply_len);
	if (reply_msg == NULL) {
		/*
		 * luaL_loadbuffer() and lua_pcall() must have
		 * pushed an error string if they failed.
		 */
		RTE_VERIFY(ret == 0);

		G_LOG(ERR,
			"The client request script returns a NULL string\n");
		lua_pop(lua_state, 1);
		return reply_client_message(conn_fd,
			CLIENT_PROC_ERROR, strlen(CLIENT_PROC_ERROR));
	}

	if (reply_len > MSG_MAX_LEN) {
		G_LOG(WARNING,
			"The reply message length (%lu) exceeds the limit\n",
			reply_len);
		reply_len = MSG_MAX_LEN;
	}

	ret = reply_client_message(conn_fd, reply_msg, reply_len);
	lua_pop(lua_state, 1);
	return ret;
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

	/*
	 * The connection with the client is closed.
	 * This is expected for clients that send one
	 * message and then close the connection.
	 */
	if (recv_size == 0) {
		G_LOG(DEBUG, "Client disconnected\n");
		return -1;
	}

	if (recv_size < 0) {
		G_LOG(ERR,
			"Failed to read data from the socket connection - (%s)\n",
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

	if (dy_conf->gt != NULL) {
		gt_conf_put(dy_conf->gt);
		dy_conf->gt = NULL;
	}

	if (dy_conf->sock_fd != -1) {
		ret = close(dy_conf->sock_fd);
		if (ret < 0) {
			G_LOG(ERR,
				"Failed to close the server socket - (%s)\n",
				strerror(errno));
		}
		dy_conf->sock_fd = -1;
	}

	rte_free(dy_conf->dynamic_config_file);
	dy_conf->dynamic_config_file = NULL;

	rte_free(dy_conf->lua_dy_base_dir);
	dy_conf->lua_dy_base_dir = NULL;

	if (dy_conf->server_path != NULL) {
		ret = unlink(dy_conf->server_path);
		if (ret != 0) {
			G_LOG(WARNING, "Failed to unlink(%s) - (%s)\n",
				dy_conf->server_path, strerror(errno));
		}

		rte_free(dy_conf->server_path);
		dy_conf->server_path = NULL;
	}

	destroy_mailbox(&dy_conf->mb);
}

static void
process_return_message(lua_State *l, struct dynamic_config *dy_conf,
	int num_succ_sent_inst)
{
	int num_gt_messages = 0;
	size_t reply_len = 0;
	char reply_msg[MSG_MAX_LEN];

	/* Wait for all GT instances to synchronize. */
	while (rte_atomic16_read(&dy_conf->num_returned_instances)
			< num_succ_sent_inst)
		rte_pause();

	while (num_gt_messages < num_succ_sent_inst) {
		int i;
		struct dy_cmd_entry *dy_cmds[dy_conf->mailbox_burst_size];
		/* Load a set of commands from its mailbox ring. */
		int num_cmd = mb_dequeue_burst(&dy_conf->mb,
			(void **)dy_cmds, dy_conf->mailbox_burst_size);
		/*
		 * This condition check deals with the possibility that
		 * the GT blocks incremented dy_conf->num_returned_instances
		 * without sending a message due to not having enough memory
		 * to send the message.
		 */
		if (num_cmd == 0)
			break;

		for (i = 0; i < num_cmd; i++) {
			struct dy_cmd_entry *entry = dy_cmds[i];
			switch (entry->op) {
				case GT_UPDATE_POLICY_RETURN: {

					if (dy_conf->gt == NULL) {
						G_LOG(ERR, "The command operation %u requires that the server runs as Grantor\n",
							entry->op);
						break;
					}

					if (unlikely(entry->u.gt.length > RETURN_MSG_MAX_LEN))
						G_LOG(ERR, "The return message from GT block is too long\n");
					else if (unlikely(reply_len + entry->u.gt.length >
							MSG_MAX_LEN))
						G_LOG(ERR, "The aggregated return message from GT blocks is too long\n");
					else {
						rte_memcpy(reply_msg + reply_len,
							entry->u.gt.return_msg,
							entry->u.gt.length);
						reply_len += entry->u.gt.length;
					}

					num_gt_messages++;
					break;
				}
				default:
					G_LOG(ERR, "Unknown command operation %u\n",
						entry->op);
					break;
			}

			mb_free_entry(&dy_conf->mb, entry);
		}
	}

	if (dy_conf->gt != NULL && num_gt_messages != dy_conf->gt->num_lcores) {
		G_LOG(WARNING,
			"%s(): successfully collected only %d/%d instances\n",
			__func__, num_gt_messages, dy_conf->gt->num_lcores);
	}

	lua_pushlstring(l, reply_msg, reply_len);
}

static int
l_update_gt_lua_states_incrementally(lua_State *l)
{
	int i;
	uint32_t ctypeid;
	struct gt_config *gt_conf;
	uint32_t correct_ctypeid_gt_config = luaL_get_ctypeid(l,
		CTYPE_STRUCT_GT_CONFIG_PTR);
	size_t len;
	const char *lua_bytecode;
	int is_returned;
	int num_succ_sent_inst = 0;
	struct dynamic_config *dy_conf = get_dy_conf();

	/* First argument must be of type CTYPE_STRUCT_GT_CONFIG_PTR. */
	void *cdata = luaL_checkcdata(l, 1,
		&ctypeid, CTYPE_STRUCT_GT_CONFIG_PTR);
	if (ctypeid != correct_ctypeid_gt_config)
		luaL_error(l, "Expected `%s' as first argument",
			CTYPE_STRUCT_GT_CONFIG_PTR);

	gt_conf = *(struct gt_config **)cdata;

	/* Second argument must be a Lua bytecode. */
	lua_bytecode = lua_tolstring(l, 2, &len);
	if (lua_bytecode == NULL || len == 0)
		luaL_error(l, "gt: invalid lua bytecode\n");

	/* Third argument should be a boolean. */
	is_returned = lua_toboolean(l, 3);

	if (lua_gettop(l) != 3)
		luaL_error(l, "Expected three arguments, however it got %d arguments",
			lua_gettop(l));

	if (is_returned)
		rte_atomic16_init(&dy_conf->num_returned_instances);

	for (i = 0; i < gt_conf->num_lcores; i++) {
		int ret;
		struct gt_instance *instance = &gt_conf->instances[i];
		unsigned int lcore_id = gt_conf->lcores[i];
		struct gt_cmd_entry *entry;
		char *lua_bytecode_buff = rte_malloc_socket("lua_bytecode",
			len, 0, rte_lcore_to_socket_id(lcore_id));
		if (lua_bytecode_buff == NULL) {
			if (num_succ_sent_inst > 0) {
				G_LOG(ERR, "gt: failed to send new lua update chunk bytecode to GT block %d at lcore %d due to failure of allocating memory\n",
					i, lcore_id);
				continue;
			} else {
				luaL_error(l, "gt: failed to send new lua update chunk bytecode to GT block %d at lcore %d due to failure of allocating memory\n",
					i, lcore_id);
			}
		}

		entry = mb_alloc_entry(&instance->mb);
		if (entry == NULL) {
			rte_free(lua_bytecode_buff);

			if (num_succ_sent_inst > 0) {
				G_LOG(ERR, "gt: failed to send new lua update chunk bytecode to GT block %d at lcore %d\n",
					i, lcore_id);
				continue;
			} else {
				luaL_error(l, "gt: failed to send new lua update chunk bytecode to GT block %d at lcore %d\n",
					i, lcore_id);
			}
		}

		entry->op = GT_UPDATE_POLICY_INCREMENTALLY;
		entry->u.bc.len = len;
		entry->u.bc.lua_bytecode = lua_bytecode_buff;
		rte_memcpy(lua_bytecode_buff, lua_bytecode, len);
		entry->u.bc.is_returned = is_returned;

		ret = mb_send_entry(&instance->mb, entry);
		if (ret != 0) {
			rte_free(lua_bytecode_buff);

			if (num_succ_sent_inst > 0) {
				G_LOG(ERR, "gt: failed to send new lua update chunk bytecode to GT block %d at lcore %d\n",
					i, lcore_id);
				continue;
			} else {
				luaL_error(l, "gt: failed to send new lua update chunk bytecode to GT block %d at lcore %d\n",
					i, lcore_id);
			}
		}

		num_succ_sent_inst++;
	}

	if (is_returned)
		process_return_message(l, dy_conf, num_succ_sent_inst);

	return !!is_returned;
}

const struct luaL_reg dylib_lua_c_funcs [] = {
	{"update_gt_lua_states", l_update_gt_lua_states},
	{"internal_update_gt_lua_states_incrementally",
		l_update_gt_lua_states_incrementally},
	{"list_gk_fib4",         l_list_gk_fib4},
	{"list_gk_fib6",         l_list_gk_fib6},
	{"list_gk_neighbors4",   l_list_gk_neighbors4},
	{"list_gk_neighbors6",   l_list_gk_neighbors6},
	{"list_lls_arp",         l_list_lls_arp},
	{"list_lls_nd",          l_list_lls_nd},
	{"ether_format_addr",    l_ether_format_addr},
	{"ip_format_addr",       l_ip_format_addr},
	{"add_grantor_entry_lb", l_add_grantor_entry_lb},
	{"update_grantor_entry_lb", l_update_grantor_entry_lb},
	{NULL,                   NULL}	/* Sentinel. */
};

static int 
setup_dy_lua(lua_State *lua_state, struct dynamic_config *dy_conf)
{
	int ret;
	char lua_entry_path[128];

	ret = snprintf(lua_entry_path, sizeof(lua_entry_path), "%s/%s",
		dy_conf->lua_dy_base_dir, dy_conf->dynamic_config_file);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(lua_entry_path));

	luaL_openlibs(lua_state);
	luaL_register(lua_state, "dylib", dylib_lua_c_funcs);
	set_lua_path(lua_state, dy_conf->lua_dy_base_dir);
	ret = luaL_loadfile(lua_state, lua_entry_path);
	if (ret != 0) {
		G_LOG(ERR, "%s\n", lua_tostring(lua_state, -1));
		return -1;
	}

	ret = lua_pcall(lua_state, 0, 0, 0);
	if (ret != 0) {
		G_LOG(ERR, "%s\n", lua_tostring(lua_state, -1));
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
		G_LOG(ERR, "Failed to accept a new connection - (%s)\n",
			strerror(errno));
		return;
	}

	if (unlikely(client_addr.sun_family != AF_UNIX)) {
		G_LOG(WARNING,
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
		G_LOG(ERR, "Failed to call setsockopt(SO_RCVTIMEO) - (%s)\n",
			strerror(errno));
		goto close_fd;
	}

	rcv_buff_size = MSG_MAX_LEN;
	ret = setsockopt(conn_fd, SOL_SOCKET,
		SO_RCVBUF, &rcv_buff_size, sizeof(rcv_buff_size));
	if (ret < 0) {
		G_LOG(ERR,
			"Failed to call setsockopt(SO_RCVBUF) with size = %d - (%s)\n",
			rcv_buff_size, strerror(errno));
		goto close_fd;
	}

	lua_state = luaL_newstate();
	if (lua_state == NULL) {
		G_LOG(ERR, "Failed to create new Lua state\n");
		goto close_fd;
	}

	/* Set up the Lua state while there is a connection. */
	ret = setup_dy_lua(lua_state, dy_conf);
	if (ret < 0) {
		G_LOG(ERR, "Failed to set up the lua state\n");
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
		G_LOG(ERR, "Failed to close the connection socket - (%s)\n",
			strerror(errno));
	}
}

static void
process_dy_cmd(struct dy_cmd_entry *entry)
{
	switch (entry->op) {
		case GT_UPDATE_POLICY_RETURN:
			G_LOG(WARNING,
				"Synchronization timeout: the return message (%s) with command operation %u from GT instance running at lcore %u did not get aggregated\n",
				entry->u.gt.return_msg, entry->op, entry->u.gt.gt_lcore);
			break;
		default:
			G_LOG(ERR, "Unknown command operation %u\n",
				entry->op);
			break;
	}
}

static void
clear_mailbox(struct dynamic_config *dy_conf)
{
	while (true) {
		int i;
		int num_cmd;
		struct dy_cmd_entry *dy_cmds[dy_conf->mailbox_burst_size];

		/* Load a set of commands from its mailbox ring. */
		num_cmd = mb_dequeue_burst(&dy_conf->mb,
			(void **)dy_cmds, dy_conf->mailbox_burst_size);
		if (num_cmd == 0)
			break;

		for (i = 0; i < num_cmd; i++) {
			process_dy_cmd(dy_cmds[i]);
			mb_free_entry(&dy_conf->mb, dy_cmds[i]);
		}
	}
}

static int
dyn_cfg_proc(void *arg)
{
	int ret = 0;
	struct dynamic_config *dy_conf = arg;

	G_LOG(NOTICE,
		"The Dynamic Config block is running at tid = %u\n", gettid());

	if (dy_conf->gt != NULL) {
		/*
		 * Grantor servers.
		 *
		 * When a client calls dylib.update_gt_lua_states() to
		 * reload the Lua policy of a Grantor server, the policy
		 * may need to request more hugepages from the kernel.
		 * This need can arrise, for example, when a policy allocates
		 * LPM tables.
		 *
		 * In order to obtain more hugepages, DPDK needs to access
		 * a number of control files such as files in /dev/hugepages/,
		 * file /proc/self/pagemap, and potentially more.
		 * Thus, the capability CAP_DAC_OVERRIDE is neccessary.
		 *
		 * The capability CAP_SYS_ADMIN is also needed, so DPDK can
		 * map virtual addresses into physical addresses.
		 * See details in rte_mem_virt2phy(), and
		 * the following function of the Linux kernel:
		 * fs/proc/task_mmu.c:pagemap_read().
		 *
		 * Notice that the dynamic configuration needs
		 * these capabilities because dylib.update_gt_lua_states()
		 * creates the new Lua states and then send them to
		 * the GT instances.
		 *
		 * A positive side effect of capability CAP_DAC_OVERRIDE is to
		 * allow the dynamic configuration block to remove
		 * its Unix socket while exiting.
		 */
		cap_value_t caps[] = {CAP_DAC_OVERRIDE, CAP_SYS_ADMIN};
		if (needed_caps(RTE_DIM(caps), caps) < 0) {
			G_LOG(ERR, "Could not set needed capabilities for Grantor\n");
			exiting = true;
		}
	} else {
		if (needed_caps(0, NULL) < 0) {
			G_LOG(ERR, "Could not set needed capabilities\n");
			exiting = true;
		}
	}

	while (likely(!exiting)) {
		fd_set fds;
		struct timeval stv;

		clear_mailbox(dy_conf);

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
			G_LOG(ERR,
				"Failed to call the select() function - (%s)\n",
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

	G_LOG(NOTICE, "The Dynamic Config block is exiting\n");

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
run_dynamic_config(struct net_config *net_conf,
	struct gk_config *gk_conf, struct gt_config *gt_conf,
	const char *server_path, const char *lua_dy_base_dir,
	const char *dynamic_config_file, struct dynamic_config *dy_conf,
	int mode)
{
	int ret;
	struct sockaddr_un server_addr;
	mode_t socket_umask, saved_umask;

	/*
	 * When the dynamic configuration is run for Gatekeeper,
	 * the gt_conf should be NULL.
	 * When the dynamic configuration is run for Grantor,
	 * the gk_conf should be NULL.
	 * The code works fine with both being NULL as well.
	 * This way, not only will the dynamic config block work for
	 * the Grantor case, it could work for unforeseen cases as well.
	 */
	if (net_conf == NULL || server_path == NULL ||
			lua_dy_base_dir == NULL ||
			dynamic_config_file == NULL || dy_conf == NULL) {
		ret = -1;
		goto out;
	}

	log_ratelimit_state_init(dy_conf->lcore_id,
		dy_conf->log_ratelimit_interval_ms,
		dy_conf->log_ratelimit_burst,
		dy_conf->log_level, "DYC");

	ret = init_mailbox("dy_conf", dy_conf->mailbox_max_entries_exp,
		sizeof(struct dy_cmd_entry), dy_conf->mailbox_mem_cache_size,
		dy_conf->lcore_id, &dy_conf->mb);
	if (ret < 0)
		goto out;

	dy_conf->sock_fd = -1;

	dy_conf->server_path = rte_strdup("server_path", server_path);
	if (dy_conf->server_path == NULL) {
		ret = -1;
		goto free_mb;
	}

	/*
	 * Remove any old socket and create an unnamed socket for the server.
	 */
	ret = unlink(dy_conf->server_path);
	if (ret < 0 && errno != ENOENT) {
		G_LOG(ERR, "%s(): Failed to unlink(%s), errno=%i: %s\n",
			__func__, dy_conf->server_path, errno, strerror(errno));
		goto free_server_path;
	}

	dy_conf->lua_dy_base_dir = rte_strdup(
		"lua_dy_base_dir", lua_dy_base_dir);
	if (dy_conf->lua_dy_base_dir == NULL) {
		G_LOG(ERR, "%s(): rte_strdup(%s) out of memory\n",
			__func__, lua_dy_base_dir);
		ret = -1;
		goto free_server_path;
	}

	dy_conf->dynamic_config_file = rte_strdup(
		"dynamic_config_file", dynamic_config_file);
	if (dy_conf->dynamic_config_file == NULL) {
		G_LOG(ERR, "%s(): rte_strdup(%s) out of memory\n",
			__func__, dynamic_config_file);
		ret = -1;
		goto free_dy_lua_base_dir;
	}

	/* Init the server socket. */
	dy_conf->sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (dy_conf->sock_fd < 0) {
		G_LOG(ERR, "%s(): Failed to initialize the server socket, errno=%i: %s\n",
			__func__, errno, strerror(errno));
		ret = -1;
		goto free_dynamic_config_file;
	}

	/* Name the socket. */
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;

	if (sizeof(server_addr.sun_path) <= strlen(dy_conf->server_path)) {
		G_LOG(ERR, "%s(): The server path (%s) exceeds the length limit %lu\n",
			__func__, dy_conf->server_path,
			sizeof(server_addr.sun_path));
		ret = -1;
		goto free_sock;
	}

	strcpy(server_addr.sun_path, dy_conf->server_path);

	/*
	 * fchmod(2) does not work on sockets, so the safest way to change
	 * the mode of the server socket is through umask(2).
	 */
	socket_umask = ~mode & (S_IRWXU | S_IRWXG | S_IRWXO);
	saved_umask = umask(socket_umask);

	ret = bind(dy_conf->sock_fd,
		(struct sockaddr *)&server_addr, sizeof(server_addr));
	if (ret < 0) {
		G_LOG(ERR, "%s(): Failed to bind the server socket (%s), errno=%i: %s\n",
			__func__, dy_conf->server_path, errno, strerror(errno));
		goto free_sock;
	}

	/* Restore original umask. */
	RTE_VERIFY(umask(saved_umask) == socket_umask);

	/* Change user and group of the server socket. */
	if (net_conf->pw_uid != 0) {
		/*
		 * fchown(2) does not work on sockets,
		 * so we are left with lchown(2).
		 */
		ret = lchown(dy_conf->server_path,
			net_conf->pw_uid, net_conf->pw_gid);
		if (ret < 0) {
			G_LOG(ERR, "%s(): Failed to change the owner of the server socket (%s) to uid=%u and gid=%u, errno=%i: %s\n",
				__func__, dy_conf->server_path,
				net_conf->pw_uid, net_conf->pw_gid,
				errno, strerror(errno));
			goto free_sock;
		}
	}

	/*
	 * The Dynamic config component listens to a Unix socket
	 * for request from the local host.
	 */
	ret = listen(dy_conf->sock_fd, 10);
	if (ret < 0) {
		G_LOG(ERR, "%s(): Failed to listen on the server socket (%s), errno=%i: %s\n",
			__func__, dy_conf->server_path, errno, strerror(errno));
		goto free_sock;
	}

	if (gk_conf != NULL)
		gk_conf_hold(gk_conf);
	dy_conf->gk = gk_conf;

	if (gt_conf != NULL)
		gt_conf_hold(gt_conf);
	dy_conf->gt = gt_conf;

	ret = launch_at_stage3("dynamic_conf",
		dyn_cfg_proc, dy_conf, dy_conf->lcore_id);
	if (ret < 0)
		goto put_gk_gt_config;

	return 0;

put_gk_gt_config:
	dy_conf->gk = NULL;
	if (gk_conf != NULL)
		gk_conf_put(gk_conf);
	dy_conf->gt = NULL;
	if (gt_conf != NULL)
		gt_conf_put(gt_conf);
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
free_mb:
	destroy_mailbox(&dy_conf->mb);
out:
	return ret;
}
