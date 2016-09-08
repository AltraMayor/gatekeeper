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

#include "gatekeeper_bp.h"
#include "gatekeeper_catcher.h"
#include "gatekeeper_config.h"
#include "gatekeeper_cps.h"
#include "gatekeeper_ggu.h"
#include "gatekeeper_gk.h"
#include "gatekeeper_gt.h"
#include "gatekeeper_lls.h"
#include "gatekeeper_rt.h"

int
config_and_launch(void)
{
	struct bp_config bp_conf;
	struct catcher_config catcher_conf;
	struct dynamic_config dy_conf;
	struct cps_config cps_conf;
	struct ggu_config ggu_conf;
	struct gk_config gk_conf;
	struct gt_config gt_conf;
	struct rt_config rt_conf;
	int ret;

	/*
	 * TODO Read in configuration file(s) using Lua and create
	 * config structs for each functional block. Then launch
	 * all functional blocks (with their config struct) that
	 * are needed with their own lcore(s).
	 */

	/*
	 * TODO Decide which lcore*s* will be assigned to BP and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_bp(&bp_conf);
	if (ret < 0)
		return ret;

	/*
	 * TODO Decide which lcore will be assigned to Catcher and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_catcher(&catcher_conf);
	if (ret < 0)
		return ret;

	/*
	 * TODO Decide which lcore will be assigned to Dynamic Config and
	 * decide what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_dynamic_config(&dy_conf);
	if (ret < 0)
		return ret;

	/*
	 * TODO Decide which lcore will be assigned to Control Plane Support
	 * and decide what other configuration information should be passed
	 * to this functional block.
	 */
	ret = run_cps(&cps_conf);
	if (ret < 0)
		return ret;

	/*
	 * TODO Decide which lcore will be assigned to GK-GT Unit and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_ggu(&ggu_conf);
	if (ret < 0)
		return ret;

	/*
	 * TODO Decide which lcore*s* will be assigned to GK and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_gk(&gk_conf);
	if (ret < 0)
		return ret;

	/*
	 * TODO Decide which lcore*s* will be assigned to GT and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_gt(&gt_conf);
	if (ret < 0)
		return ret;

	/*
	 * TODO Decide which lcore will be assigned to LLS and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_lls();
	if (ret < 0)
		return ret;

	/*
	 * TODO Decide which lcore*s* will be assigned to RT and decide
	 * what other configuration information should be passed to
	 * this functional block.
	 */
	ret = run_rt(&rt_conf);
	return ret;
}
