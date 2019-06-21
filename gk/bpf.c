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

#include "gatekeeper_gk.h"
#include "bpf.h"

static const struct rte_bpf_xsym flow_handler_init_xsym[] = {
};

static const struct rte_bpf_xsym flow_handler_pkt_xsym[] = {
};

static int
__bpf_jit_if_possible(struct rte_bpf *bpf, rte_bpf_jitted_func_t *ret_f,
	unsigned int index, const char *name)
{
	struct rte_bpf_jit jit;

	int rc = rte_bpf_get_jit(bpf, &jit);
	if (unlikely(rc != 0)) {
		GK_LOG(ERR, "%s() failed to get JIT program %s at index %u, error code: %i\n",
			__func__, name, index, rc);
		return rc;
	}

	if (unlikely(jit.func == NULL)) {
		GK_LOG(WARNING, "%s(): BPF JIT is not available\n", __func__);
		return -ENOTSUP;
	}

	*ret_f = jit.func;
	return 0;
}

#define bpf_jit_if_possible(bpf, ret, index) \
	__bpf_jit_if_possible(bpf, ret, index, #bpf)

int
gk_load_bpf_flow_handler(struct gk_config *gk_conf, unsigned int index,
	const char *filename, int jit)
{
	struct gk_bpf_flow_handler *handler;
	struct rte_bpf_prm prm;
	struct rte_bpf *bpf_f_init;

	if (gk_conf == NULL) {
		GK_LOG(ERR, "%s(): parameter gk_conf cannot be NULL\n",
			__func__);
		return -1;
	}

	if (index >= GK_MAX_BPF_FLOW_HANDLERS) {
		GK_LOG(ERR,
			"%s(): parameter index must be in [0, %i], received %u\n",
			__func__, GK_MAX_BPF_FLOW_HANDLERS, index);
		return -1;
	}

	handler = &gk_conf->flow_handlers[index];
	if (handler->f_init != NULL || handler->f_pkt != NULL) {
		GK_LOG(ERR, "%s(): index %i is already in use\n",
			__func__, index);
		return -1;
	}

	memset(&prm, 0, sizeof(prm));
	prm.xsym = flow_handler_init_xsym;
	prm.nb_xsym = RTE_DIM(flow_handler_init_xsym);
	bpf_f_init = rte_bpf_elf_load(&prm, filename, "init");
	if (bpf_f_init == NULL) {
		GK_LOG(ERR,
			"%s(): file \"%s\" does not have the BPF program \"init\"; rte_errno = %i: %s\n",
			__func__, filename, rte_errno, strerror(rte_errno));
		return -1;
	}

	prm.xsym = flow_handler_pkt_xsym;
	prm.nb_xsym = RTE_DIM(flow_handler_pkt_xsym);
	handler->f_pkt = rte_bpf_elf_load(&prm, filename, "pkt");
	if (handler->f_pkt == NULL) {
		GK_LOG(ERR,
			"%s(): file \"%s\" does not have the BPF program \"pkt\"; rte_errno = %i: %s\n",
			__func__, filename, rte_errno, strerror(rte_errno));
		goto f_init;
	}

	if (jit && bpf_jit_if_possible(bpf_f_init,
			&handler->f_init_jit, index) == 0)
		bpf_jit_if_possible(handler->f_pkt, &handler->f_pkt_jit, index);

	/*
	 * Guarantee that @handler has all its field but f_init properly set
	 * in memory. This is important because the Dynamic Configuration
	 * Block may call this function during runtime.
	 */
	rte_mb();
	handler->f_init = bpf_f_init;
	return 0;

f_init:
	rte_bpf_destroy(bpf_f_init);
	return -1;
}
