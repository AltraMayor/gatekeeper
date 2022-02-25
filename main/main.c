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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <inttypes.h>
#include <argp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_log.h>
#include <rte_common.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_timer.h>

#include "gatekeeper_main.h"
#include "gatekeeper_config.h"
#include "gatekeeper_net.h"
#include "gatekeeper_launch.h"

/* Indicates whether the program needs to exit or not. */
volatile int exiting = false;

/*
 * These metrics are system dependent, and 
 * initialized via time_resolution_init() function.
 */
uint64_t cycles_per_sec;
uint64_t cycles_per_ms;
uint64_t picosec_per_cycle;

const char *log_file_name_format;
const char *log_base_dir;
mode_t log_file_mode;

/* Argp's global variables. */
const char *argp_program_version = "Gatekeeper 1.0";

/* Arguments. */
static char adoc[] = "";

static char doc[] = "Gatekeeper -- the first open source "
	"DDoS protection system";

static struct argp_option options[] = {
	{"lua-base-dir", 'd', "DIR", 0,
		"Base directory DIR for Gatekeeper Lua files", 0},
	{"gatekeeper-config-file", 'f', "FILE", 0,
		"Lua configuration FILE to initialize Gatekeeper", 0},
	{"log-file-name-format", 'l', "FORMAT", 0,
		"The name format of log files", 0},
	{"log-base-dir", 'g', "DIR", 0,
		"Base directory DIR for Gatekeeper log files", 0},
	{"log-file-mode", 'm', "MODE", 0,
		"The mode of log files", 0},
	{ 0 }
};

struct args {
	const char *lua_base_dir;
	const char *gatekeeper_config_file;
	const char *log_file_name_format;
	const char *log_base_dir;
	mode_t     log_file_mode;
};

#define MAX_MODE (07777)

static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
	struct args *args = state->input;

	switch (key) {
	case 'd':
		args->lua_base_dir = arg;
		break;

	case 'f':
		args->gatekeeper_config_file = arg;
		break;

	case 'l':
		args->log_file_name_format = arg;
		break;

	case 'g':
		args->log_base_dir = arg;
		break;

	case 'm': {
		long mode;
		char *end;

		/* Assuming the file mode is in octal. */
		mode = strtol(arg, &end, 8);
		if (!*arg || *end) {
			argp_error(state, "the log file mode \"%s\" is not an number",
				arg);
		}
		RTE_BUILD_BUG_ON(LONG_MIN >= 0 || MAX_MODE >= LONG_MAX);
		if (mode < 0 || MAX_MODE < mode) {
			argp_error(state, "the log file mode \"%s\" is out of range",
				arg);
		}
		args->log_file_mode = mode;
		break;
	}

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = {options, parse_opt, adoc, doc, NULL, NULL, NULL};

char *
rte_strdup(const char *type, const char *s)
{
	int len = s == NULL ? 0 : strlen(s) + 1;
	char *res = rte_malloc(type, len, 0);
	if (unlikely(res == NULL))
		return NULL;

	return strcpy(res, s);
}

FILE *log_file;

static void
cleanup_log(void)
{
	if (log_file != NULL) {
		if (log_file != stderr)
			fclose(log_file);
		log_file = NULL;
	}
}

int
gatekeeper_log_init(void)
{
	int ret;
	int log_fd;
	time_t now;
	struct tm time_info;
	char log_file_name[128];
	char log_file_path[512];
	FILE *new_log_file;

	if (log_file == NULL) {
		/*
		 * Initialize log_file with stderr to guarantee that log_file
		 * has a valid value even before a file is open.
		 */
		log_file = stderr;
	}

	now = time(&now);
	RTE_VERIFY(localtime_r(&now, &time_info) == &time_info);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
	ret = strftime(log_file_name, sizeof(log_file_name),
		log_file_name_format, &time_info);
#pragma GCC diagnostic pop
	if (!(ret > 0 && ret < (int)sizeof(log_file_name))) {
		G_LOG(ERR, "gatekeeper: Failed to call strftime() to format the log file name\n");
		return -1;
	}

	ret = snprintf(log_file_path, sizeof(log_file_path),
		"%s/%s", log_base_dir, log_file_name);
	if (!(ret > 0 && ret < (int)sizeof(log_file_path))) {
		G_LOG(ERR, "gatekeeper: Failed to call snprintf() to fill up the log file path\n");
		return -1;
	}

	log_fd = open(log_file_path, O_CREAT | O_WRONLY, log_file_mode);
	if (log_fd < 0) {
		G_LOG(ERR, "gatekeeper: Failed to get log file descriptor %s - %s\n",
			log_file_path, strerror(errno));
		return -1;
	}

	new_log_file = fdopen(log_fd, "a");
	if (new_log_file == NULL) {
		G_LOG(ERR, "gatekeeper: Failed to open log file %s - %s\n",
			log_file_path, strerror(errno));
		close(log_fd);
		return -1;
	}

	ret = rte_openlog_stream(new_log_file);
	if (ret != 0) {
		fclose(new_log_file);
		return -1;
	}

	if (log_file != stderr)
		fclose(log_file);
	log_file = new_log_file;

	return log_fd;
}

/* Obtain the system time resolution. */
static int
time_resolution_init(void)
{
	int ret;
	uint64_t diff_ns;
	uint64_t cycles;
	uint64_t tsc_start;
	struct timespec tp_start;

	tsc_start = rte_rdtsc();
	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &tp_start);
	if (ret < 0)
		return ret;

	while (1) {
		uint64_t tsc_now;
		struct timespec tp_now;

		ret = clock_gettime(CLOCK_MONOTONIC_RAW, &tp_now);
		tsc_now = rte_rdtsc();
		if (ret < 0)
			return ret;

		diff_ns = (uint64_t)(tp_now.tv_sec - tp_start.tv_sec) * 1000000000UL 
				+ (uint64_t)(tp_now.tv_nsec - tp_start.tv_nsec);

		if (diff_ns >= 1000000000UL) {
			cycles = tsc_now - tsc_start;
			break;
		}
	}

	cycles_per_sec = cycles * 1000000000UL / diff_ns;
	cycles_per_ms = cycles_per_sec / 1000UL;
	picosec_per_cycle = 1000UL * diff_ns / cycles;

	G_LOG(NOTICE,
		"main: cycles/second = %" PRIu64 ", cycles/millisecond = %" PRIu64 ", picosec/cycle = %" PRIu64 "\n",
		cycles_per_sec, cycles_per_ms, picosec_per_cycle);

	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT)
		fprintf(stderr, "caught SIGINT\n");
	else if (signum == SIGTERM)
		fprintf(stderr, "caught SIGTERM\n");
	else
		fprintf(stderr, "caught unknown signal (%d)\n", signum);
	exiting = true;
}

static int
run_signal_handler(void)
{
	int ret = -1;
	sig_t pipe_handler;
	struct sigaction new_action;
	struct sigaction old_int_action;
	struct sigaction old_term_action;

	new_action.sa_handler = signal_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;
	
	ret = sigaction(SIGINT, &new_action, &old_int_action);
	if (ret < 0)
		goto out;

	ret = sigaction(SIGTERM, &new_action, &old_term_action);
	if (ret < 0)
		goto int_action;

	pipe_handler = signal(SIGPIPE, SIG_IGN);
	if (pipe_handler == SIG_ERR) {
		fprintf(stderr, "Error: failed to ignore SIGPIPE - %s\n",
			strerror(errno));
		goto term_action;
	}

	goto out;

term_action:
	sigaction(SIGTERM, &old_term_action, NULL);
int_action:
	sigaction(SIGINT, &old_int_action, NULL);
out:
	return ret;
}

int
main(int argc, char **argv)
{
	struct args args = {
		/* Defaults. */
		.lua_base_dir = "./lua",
		.gatekeeper_config_file = "main_config.lua",
		.log_file_name_format = "gatekeeper_%Y_%m_%d_%H_%M.log",
		.log_base_dir = ".",
		.log_file_mode = S_IRUSR | S_IWUSR,
	};
	int ret, log_fd;

	/*
	 * Functional blocks have their own log level, and all log entries of
	 * Gatekeeper use BLOCK_LOGTYPE. Thus, setting BLOCK_LOGTYPE to DEBUG
	 * level instructs DPDK to log everything that the blocks decide to
	 * log.
	 */
	ret = rte_log_set_level(BLOCK_LOGTYPE, RTE_LOG_DEBUG);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error while setting log level of BLOCK_LOGTYPE\n");

	/*
	 * rte_eal_init(), which is called next, creates all threads that
	 * Gatekeeper will use before the code finds out if Gatekeeper is
	 * going to run as root or not. When Gatekeeper runs with a
	 * non-root user, Gatekeeper has to assign capabilities to the
	 * functional blocks, which, in turn, is only possible if the flag
	 * PR_SET_KEEPCAPS is already set.
	 */
	RTE_VERIFY(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0);

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Parse Gatekeeper arguments (after the EAL ones). */
	ret = argp_parse(&argp, argc, argv, 0, NULL, &args);
	if (ret != 0)
		rte_exit(EXIT_FAILURE, "Invalid Gatekeeper parameters\n");

	log_file_name_format = args.log_file_name_format;
	log_base_dir = args.log_base_dir;
	log_file_mode = args.log_file_mode;

	/*
	 * ATTENTION: this is the only place at which the macro RTE_LOG()
	 * should be used, everywhere else should use one of Gatekeeper's
	 * log macros.
	 *
	 * The log level ALERT is used here to guarantee that
	 * the message will be logged.
	 * While the log level EMERG would raise this guarantee,
	 * it is not used here to avoid broadcasting the message throughout
	 * the system.
	 */
	RTE_LOG(ALERT, EAL, "See files in %s for further log\n", log_base_dir);
	ret = gatekeeper_log_init();
	if (ret < 0)
		goto out;
	log_fd = ret;

	/* Used by the LLS block. */
	rte_timer_subsystem_init();

	/* Given the nature of signal, it's okay to not have a cleanup for them. */
	ret = run_signal_handler();
	if (ret < 0)
		goto log;

	/*
	 * Given the nature of 'clock_gettime()' call, it's okay to not have a 
	 * cleanup for them.
	 */
	ret = time_resolution_init();
	if (ret < 0)
		goto log;

	ret = config_gatekeeper(args.lua_base_dir, args.gatekeeper_config_file);
	if (ret < 0) {
		G_LOG(ERR, "main: failed to configure Gatekeeper\n");
		goto net;
	}

	/*
	 * Finalize any network configuration, such as building ACL tries,
	 * after blocks have had a chance to make use of network state
	 * during stage 2. This is needed because there is no stage 3 for
	 * the network configuration.
	 *
	 * Finalize any user configuration, such as changing file permissions
	 * and dropping user privileges.
	 */
	ret = launch_at_stage2(finalize_stage2, (void *)(intptr_t)log_fd);
	if (ret < 0)
		goto net;

	ret = launch_gatekeeper();
	if (ret < 0)
		exiting = true;

	rte_eal_mp_wait_lcore();
net:
	gatekeeper_free_network();
log:
	cleanup_log();
out:
	return ret;
}
