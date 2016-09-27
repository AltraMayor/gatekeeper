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
#include <stdbool.h>
#include <signal.h>

#include <rte_eal.h>
#include <rte_log.h>
#include <rte_common.h>
#include <rte_launch.h>

#include "gatekeeper_config.h"
#include "gatekeeper_net.h"

/* Indicates whether the program needs to exit or not. */
volatile int exiting = false;

static void
signal_handler(int signum)
{
	if (signum == SIGINT)
		fprintf(stderr, "caught SIGINT\n");
	else if (signum == SIGTERM)
		fprintf(stderr, "caught SIGTERM\n");
	else
		fprintf(stderr, "caught unknown signal\n");
	exiting = true;
}

static int
run_signal_handler(void)
{
	int ret = -1;
	struct sigaction new_action;
	struct sigaction old_int_action;

	new_action.sa_handler = signal_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;
	
	ret = sigaction(SIGINT, &new_action, &old_int_action);
	if (ret < 0)
		goto out;

	ret = sigaction(SIGTERM, &new_action, NULL);
	if (ret < 0)
		goto int_action;

	goto out;

int_action:
	sigaction(SIGINT, &old_int_action, NULL);
out:
	return ret;
}

int
main(int argc, char **argv)
{
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization!\n");

	/* XXX Set the global log level. Change it as needed. */
	rte_set_log_level(RTE_LOG_DEBUG);

	/* Given the nature of signal, it's okay to not have a cleanup for them. */
	ret = run_signal_handler();
	if (ret < 0)
		goto out;

	ret = gatekeeper_init_network();
	if (ret < 0)
		goto out;

	/*
	 * TODO Set up shared state (such as mailboxes) and figure out
	 * how to pass that information to the functional blocks that
	 * need it.
	 */

	ret = config_and_launch();
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Fail to initialize Gatekeeper!\n");
	}

	rte_eal_mp_wait_lcore();

	/* TODO Perform any needed state destruction. */

	gatekeeper_free_network();
out:
	return ret;
}
