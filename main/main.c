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

#include "gatekeeper_arp.h"
#include "gatekeeper_bp.h"
#include "gatekeeper_catcher.h"
#include "gatekeeper_config.h"
#include "gatekeeper_cps.h"
#include "gatekeeper_ggu.h"
#include "gatekeeper_gk.h"
#include "gatekeeper_gt.h"
#include "gatekeeper_rt.h"
#include "gatekeeper_main.h"

#include "gatekeeper_net.h"
#include "gatekeeper_mailbox.h"

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

	/*
	 * TODO Add configuration state that can be written by this
	 * function, so its information can be used to call the
	 * functional blocks below.
	 */
	ret = get_static_config();
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

	/*
	 * TODO Decide whether this instance of the application is
	 * running GK or GT and adjust which functional blocks are
	 * invoked accordingly.
	 */

	/*
	 * TODO Each of the calls below to a functional block should
	 * be spun out of its own lcore (or set of lcores).
	 */

	/*
	 * TODO Decide which lcore will be assigned to ARP and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_arp();
	if (ret < 0)
		goto net;

	/*
	 * TODO Decide which lcore*s* will be assigned to BP and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_bp();
	if (ret < 0)
		goto net;

	/*
	 * TODO Decide which lcore will be assigned to Catcher and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_catcher();
	if (ret < 0)
		goto net;

	/*
	 * TODO Decide which lcore will be assigned to Dynamic Config and
	 * decide what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_dynamic_config();
	if (ret < 0)
		goto net;

	/*
	 * TODO Decide which lcore will be assigned to Control Plane Support
	 * and decide what other configuration information should be passed
	 * to this functional block.
	 */
	ret = run_cps();
	if (ret < 0)
		goto net;

	/*
	 * TODO Decide which lcore will be assigned to GK-GT Unit and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_ggu();
	if (ret < 0)
		goto net;

	/*
	 * TODO Decide which lcore*s* will be assigned to GK and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_gk();
	if (ret < 0)
		goto net;

	/*
	 * TODO Decide which lcore*s* will be assigned to GT and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_gt();
	if (ret < 0)
		goto net;

	/*
	 * TODO Decide which lcore*s* will be assigned to RT and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_rt();

	rte_eal_mp_wait_lcore();

	/*
	 * TODO Perform any needed state destruction, stop lcores if one
	 * of the functions returned with an error, etc.
	 */

net:
	gatekeeper_free_network();
out:
	return ret;
}
