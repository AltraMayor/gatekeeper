/* XXX Which license should be placed here? */

#include <stdio.h>

#include <rte_eal.h>

#include "gatekeeper_arp.h"
#include "gatekeeper_bp.h"
#include "gatekeeper_catcher.h"
#include "gatekeeper_config.h"
#include "gatekeeper_cps.h"
#include "gatekeeper_ggu.h"
#include "gatekeeper_gk.h"
#include "gatekeeper_gt.h"
#include "gatekeeper_rt.h"

#include "gatekeeper_mailbox.h"

int
main(int argc, char **argv)
{
	int ret = rte_eal_init(argc, argv);
	printf("EAL initialization: %d\n", ret);

	/*
	 * TODO Add configuration state that can be written by this
	 * function, so its information can be used to call the
	 * functional blocks below.
	 */
	ret = get_static_config();
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
		goto out;

	/*
	 * TODO Decide which lcore*s* will be assigned to BP and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_bp();
	if (ret < 0)
		goto out;

	/*
	 * TODO Decide which lcore will be assigned to Catcher and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_catcher();
	if (ret < 0)
		goto out;

	/*
	 * TODO Decide which lcore will be assigned to Dynamic Config and
	 * decide what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_dynamic_config();
	if (ret < 0)
		goto out;

	/*
	 * TODO Decide which lcore will be assigned to Control Plane Support
	 * and decide what other configuration information should be passed
	 * to this functional block.
	 */
	ret = run_cps();
	if (ret < 0)
		goto out;

	/*
	 * TODO Decide which lcore will be assigned to GK-GT Unit and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_ggu();
	if (ret < 0)
		goto out;

	/*
	 * TODO Decide which lcore*s* will be assigned to GK and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_gk();
	if (ret < 0)
		goto out;

	/*
	 * TODO Decide which lcore*s* will be assigned to GT and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_gt();
	if (ret < 0)
		goto out;

	/*
	 * TODO Decide which lcore*s* will be assigned to RT and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_rt();

out:
	/*
	 * TODO Perform any needed state destruction, stop lcores if one
	 * of the functions returned with an error, etc.
	 */

	return ret;
}
