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

#include <rte_ip_frag.h>

#define GK_BPF_INTERNAL static
#include "gatekeeper_flow_bpf.h"

#include "gatekeeper_gk.h"
#include "gatekeeper_main.h"
#include "gatekeeper_l2.h"
#include "gatekeeper_varip.h"

#include "bpf.h"

struct gk_bpf_init_frame {
	uint64_t		password;
	struct gk_bpf_cookie	*cookie;
	struct gk_bpf_init_ctx	ctx;
};

static const uint64_t init_password = 0xe0952bafb0a248f5;

static struct gk_bpf_init_frame *
init_ctx_to_frame(struct gk_bpf_init_ctx *ctx)
{
	struct gk_bpf_init_frame *frame;

	if (unlikely(ctx == NULL))
		return NULL;

	frame = container_of(ctx, struct gk_bpf_init_frame, ctx);
	if (unlikely(frame->password != init_password)) {
		G_LOG(WARNING, "%s(): password violation\n", __func__);
		return NULL;
	}

	return frame;
}

static struct gk_bpf_cookie *
init_ctx_to_cookie(struct gk_bpf_init_ctx *ctx)
{
	struct gk_bpf_init_frame *frame = init_ctx_to_frame(ctx);
	if (unlikely(frame == NULL))
		return NULL;
	return frame->cookie;
}

static const struct rte_bpf_xsym flow_handler_init_xsym[] = {
	{
		.name = "cycles_per_sec",
		.type = RTE_BPF_XTYPE_VAR,
		.var = {
			.val = &cycles_per_sec,
			.desc = {
				.type = RTE_BPF_ARG_PTR,
				.size = sizeof(cycles_per_sec),
			},
		},
	},
	{
		.name = "cycles_per_ms",
		.type = RTE_BPF_XTYPE_VAR,
		.var = {
			.val = &cycles_per_ms,
			.desc = {
				.type = RTE_BPF_ARG_PTR,
				.size = sizeof(cycles_per_ms),
			},
		},
	},
	{
		.name = "init_ctx_to_cookie",
		.type = RTE_BPF_XTYPE_FUNC,
		.func = {
			.val = (void *)init_ctx_to_cookie,
			.nb_args = 1,
			.args = {
				[0] = {
					.type = RTE_BPF_ARG_PTR,
					.size = sizeof(struct gk_bpf_init_ctx),
				},
			},
			.ret = {
				.type = RTE_BPF_ARG_PTR,
				.size = sizeof(struct gk_bpf_cookie),
			},
		},
	},
};

struct gk_bpf_pkt_frame {
	uint64_t		password;
	struct flow_entry	*fe;
	struct ipacket          *packet;
	struct gk_config	*gk_conf;
	bool			ready_to_tx;
	struct gk_bpf_pkt_ctx	ctx;
};

static const uint64_t pkt_password = 0xa2e329ba8b15af05;

static struct gk_bpf_pkt_frame *
pkt_ctx_to_frame(struct gk_bpf_pkt_ctx *ctx)
{
	struct gk_bpf_pkt_frame *frame;

	if (unlikely(ctx == NULL))
		return NULL;

	frame = container_of(ctx, struct gk_bpf_pkt_frame, ctx);
	if (unlikely(frame->password != pkt_password)) {
		G_LOG(WARNING, "%s(): password violation\n", __func__);
		return NULL;
	}

	return frame;
}

static struct gk_bpf_cookie *
pkt_ctx_to_cookie(struct gk_bpf_pkt_ctx *ctx)
{
	struct gk_bpf_pkt_frame *frame = pkt_ctx_to_frame(ctx);
	if (unlikely(frame == NULL))
		return NULL;
	return &frame->fe->u.bpf.cookie;
}

static struct rte_mbuf *
pkt_ctx_to_pkt(struct gk_bpf_pkt_ctx *ctx)
{
	struct gk_bpf_pkt_frame *frame = pkt_ctx_to_frame(ctx);
	if (unlikely(frame == NULL))
		return NULL;
	return frame->packet->pkt;
}

/*
 * One's complement sum.
 *
 * Notice that if @a and @b are little-endian, the result is also
 * little-endian. The same is true for big-endian. In order words,
 * this function preserves endianness.
 *
 * The endianness preservation is independent of the endianness of the host.
 */
static inline uint16_t
onec_add(uint16_t a, uint16_t b)
{
	uint16_t res = a + b;
	return res + (res < b);
}

/*
 * The result has the same endianness of the inputs as long as
 * all inputs have the same endianness.
 * The endianness preservation is independent of the endianness of the host.
 */
static inline uint16_t
new_ip_csum(uint16_t old_csum, uint16_t old16, uint16_t new16)
{
	/* According to RFC1624 [Eqn. 3]. */
	return ~onec_add(onec_add(~old_csum, ~old16), new16);
}

static int
update_pkt_priority(struct ipacket *packet, int priority,
	struct gatekeeper_if *iface)
{
	uint32_t mask;
	struct rte_ether_hdr *eth_hdr = adjust_pkt_len(packet->pkt, iface, 0);
	if (eth_hdr == NULL) {
		G_LOG(ERR, "gk: could not adjust the packet length at %s\n",
			__func__);
		return -1;
	}

	RTE_VERIFY(pkt_out_skip_l2(iface, eth_hdr) == packet->l3_hdr);

	if (packet->flow.proto == RTE_ETHER_TYPE_IPV4) {
		struct rte_ipv4_hdr *ip4hdr = packet->l3_hdr;
		uint16_t old_val = *(uint16_t *)ip4hdr;
		uint16_t new_val;

		mask = (1 << 2) - 1;

		ip4hdr->type_of_service = (priority << 2) |
			(ip4hdr->type_of_service & mask);

		new_val = *(uint16_t *)ip4hdr;

		/* According to RFC1624 [Eqn. 4]. */
		ip4hdr->hdr_checksum = new_ip_csum(ip4hdr->hdr_checksum,
			old_val, new_val);
	} else if (likely(packet->flow.proto == RTE_ETHER_TYPE_IPV6)) {
		struct rte_ipv6_hdr *ip6hdr = packet->l3_hdr;

		mask = (((1 << 4) - 1) << 28) + (1 << 22) - 1;

		ip6hdr->vtc_flow = rte_cpu_to_be_32(
			(priority << 22) |
			(rte_be_to_cpu_32(ip6hdr->vtc_flow) & mask));
	} else
		return -1;

	return 0;
}

static int
gk_bpf_prep_for_tx(struct gk_bpf_pkt_ctx *ctx, int priority,
	int direct_if_possible)
{
	int ret;
	struct gk_bpf_pkt_frame *frame = pkt_ctx_to_frame(ctx);
	if (unlikely(frame == NULL))
		return -EINVAL;

	if (unlikely(frame->ready_to_tx))
		return -EINVAL;
	if (unlikely(priority < 0 || priority > PRIORITY_MAX))
		return -EINVAL;

	ret = (direct_if_possible != 0 && priority == PRIORITY_GRANTED)
		? update_pkt_priority(frame->packet, priority,
			&frame->gk_conf->net->back)
		: encapsulate(frame->packet->pkt, priority,
			&frame->gk_conf->net->back,
			&choose_grantor_per_flow(frame->fe)->gt_addr);

	frame->ready_to_tx = ret == 0;
	return ret;
}

static const struct rte_bpf_xsym flow_handler_pkt_xsym[] = {
	{
		.name = "cycles_per_sec",
		.type = RTE_BPF_XTYPE_VAR,
		.var = {
			.val = &cycles_per_sec,
			.desc = {
				.type = RTE_BPF_ARG_PTR,
				.size = sizeof(cycles_per_sec),
			},
		},
	},
	{
		.name = "cycles_per_ms",
		.type = RTE_BPF_XTYPE_VAR,
		.var = {
			.val = &cycles_per_ms,
			.desc = {
				.type = RTE_BPF_ARG_PTR,
				.size = sizeof(cycles_per_ms),
			},
		},
	},
	{
		.name = "pkt_ctx_to_cookie",
		.type = RTE_BPF_XTYPE_FUNC,
		.func = {
			.val = (void *)pkt_ctx_to_cookie,
			.nb_args = 1,
			.args = {
				[0] = {
					.type = RTE_BPF_ARG_PTR,
					.size = sizeof(struct gk_bpf_pkt_ctx),
				},
			},
			.ret = {
				.type = RTE_BPF_ARG_PTR,
				.size = sizeof(struct gk_bpf_cookie),
			},
		},
	},
	{
		.name = "pkt_ctx_to_pkt",
		.type = RTE_BPF_XTYPE_FUNC,
		.func = {
			.val = (void *)pkt_ctx_to_pkt,
			.nb_args = 1,
			.args = {
				[0] = {
					.type = RTE_BPF_ARG_PTR,
					.size = sizeof(struct gk_bpf_pkt_ctx),
				},
			},
			.ret = {
				.type = RTE_BPF_ARG_PTR_MBUF,
				.size = sizeof(struct rte_mbuf),
				.buf_size = RTE_MBUF_DEFAULT_BUF_SIZE,
			},
		},
	},
	{
		.name = "gk_bpf_prep_for_tx",
		.type = RTE_BPF_XTYPE_FUNC,
		.func = {
			.val = (void *)gk_bpf_prep_for_tx,
			.nb_args = 3,
			.args = {
				[0] = {
					.type = RTE_BPF_ARG_PTR,
					.size = sizeof(struct gk_bpf_pkt_ctx),
				},
				[1] = {
					.type = RTE_BPF_ARG_RAW,
					.size = sizeof(int),
				},
				[2] = {
					.type = RTE_BPF_ARG_RAW,
					.size = sizeof(int),
				},
			},
			.ret = {
				.type = RTE_BPF_ARG_RAW,
				.size = sizeof(int),
			},
		},
	},
};

static int
__bpf_jit_if_possible(struct rte_bpf *bpf, rte_bpf_jitted_func_t *ret_f,
	unsigned int index, const char *name)
{
	struct rte_bpf_jit jit;

	int rc = rte_bpf_get_jit(bpf, &jit);
	if (unlikely(rc != 0)) {
		G_LOG(ERR, "%s() failed to get JIT program %s at index %u, error code: %i\n",
			__func__, name, index, rc);
		return rc;
	}

	if (unlikely(jit.func == NULL)) {
		G_LOG(WARNING, "%s(): BPF JIT is not available\n", __func__);
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
		G_LOG(ERR, "%s(): parameter gk_conf cannot be NULL\n",
			__func__);
		return -1;
	}

	if (index >= GK_MAX_BPF_FLOW_HANDLERS) {
		G_LOG(ERR,
			"%s(): parameter index must be in [0, %i], received %u\n",
			__func__, GK_MAX_BPF_FLOW_HANDLERS, index);
		return -1;
	}

	handler = &gk_conf->flow_handlers[index];
	if (handler->f_init != NULL || handler->f_pkt != NULL) {
		G_LOG(ERR, "%s(): index %i is already in use\n",
			__func__, index);
		return -1;
	}

	memset(&prm, 0, sizeof(prm));
	prm.xsym = flow_handler_init_xsym;
	prm.nb_xsym = RTE_DIM(flow_handler_init_xsym);
	prm.prog_arg.type = RTE_BPF_ARG_PTR;
	prm.prog_arg.size = sizeof(struct gk_bpf_init_ctx);
	bpf_f_init = rte_bpf_elf_load(&prm, filename, "init");
	if (bpf_f_init == NULL) {
		G_LOG(ERR,
			"%s(): file \"%s\" does not have the BPF program \"init\"; rte_errno = %i: %s\n",
			__func__, filename, rte_errno, strerror(rte_errno));
		return -1;
	}

	prm.xsym = flow_handler_pkt_xsym;
	prm.nb_xsym = RTE_DIM(flow_handler_pkt_xsym);
	prm.prog_arg.size = sizeof(struct gk_bpf_pkt_ctx);
	handler->f_pkt = rte_bpf_elf_load(&prm, filename, "pkt");
	if (handler->f_pkt == NULL) {
		G_LOG(ERR,
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

static void
fill_in_cmd_entry(struct gk_cmd_entry *entry, rte_atomic32_t *done_counter,
	void *arg)
{
	entry->op = GK_FLUSH_BPF;
	entry->u.flush_bpf.program_index = (uintptr_t)arg;
	entry->u.flush_bpf.done_counter = done_counter;
}

int
gk_unload_bpf_flow_handler(struct gk_config *gk_conf, unsigned int index)
{
	struct gk_bpf_flow_handler *handler;
	struct rte_bpf *bpf;

	if (gk_conf == NULL) {
		G_LOG(ERR, "%s(): parameter gk_conf cannot be NULL\n",
			__func__);
		return -1;
	}

	if (index >= GK_MAX_BPF_FLOW_HANDLERS) {
		G_LOG(ERR,
			"%s(): parameter index must be in [0, %i], received %u\n",
			__func__, GK_MAX_BPF_FLOW_HANDLERS, index);
		return -1;
	}

	handler = &gk_conf->flow_handlers[index];
	bpf = handler->f_init;
	if (bpf == NULL || handler->f_pkt == NULL) {
		G_LOG(ERR, "%s(): index %i is NOT in use\n",
			__func__, index);
		return -1;
	}

	/* Stop new flow entries of refering to this BPF program. */
	handler->f_init = NULL;
	handler->f_init_jit = NULL;
	rte_mb();

	/*
	 * Flush all flow entries in all flow tables that refer to
	 * this BPF program.
	 */
	synchronize_gk_instances(gk_conf, fill_in_cmd_entry,
		(void *)(uintptr_t)index);

	/*
	 * Free the BPF program.
	 */

	rte_bpf_destroy(bpf);

	bpf = handler->f_pkt;
	handler->f_pkt = NULL;
	handler->f_pkt_jit = NULL;
	rte_bpf_destroy(bpf);

	return 0;
}

int
gk_init_bpf_cookie(const struct gk_config *gk_conf, uint8_t program_index,
	struct gk_bpf_cookie *cookie)
{
	const struct gk_bpf_flow_handler *handler =
		&gk_conf->flow_handlers[program_index];
	struct rte_bpf *bpf;
	struct gk_bpf_init_frame frame;
	rte_bpf_jitted_func_t jit;
	uint64_t bpf_ret;

	bpf = handler->f_init;
	if (bpf == NULL || handler->f_pkt == NULL) {
		G_LOG(ERR, "The GK BPF program at index %u is not available\n",
			program_index);
		return -1;
	}

	frame.password = init_password;
	frame.cookie = cookie;
	frame.ctx.now = rte_rdtsc();
	jit = handler->f_init_jit;
	bpf_ret = likely(jit != NULL)
		? jit(&frame.ctx)
		: rte_bpf_exec(bpf, &frame.ctx);
	if (bpf_ret != GK_BPF_INIT_RET_OK) {
		G_LOG(ERR, "The function init of the GK BPF program at index %u returned an error\n",
			program_index);
		return -1;
	}
	return 0;
}

static int
parse_packet_further(struct ipacket *packet, struct gk_bpf_pkt_ctx *ctx)
{
	struct rte_mbuf *pkt = packet->pkt;
	uint16_t parsed_len = pkt_in_l2_hdr_len(pkt);

	pkt->l2_len = parsed_len;
	ctx->l3_proto = packet->flow.proto;

	/*
	 * extract_packet_info() guarantees that the L2 header and
	 * the L3 headers without extensions are in the packet.
	 */

	switch (packet->flow.proto) {
	case RTE_ETHER_TYPE_IPV4: {
		struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(pkt,
			struct rte_ipv4_hdr *, parsed_len);
		pkt->l3_len = ipv4_hdr_len(ipv4_hdr);
		parsed_len += pkt->l3_len;
		ctx->fragmented = rte_ipv4_frag_pkt_is_fragmented(ipv4_hdr);
		ctx->l4_proto = ipv4_hdr->next_proto_id;
		break;
	}

	case RTE_ETHER_TYPE_IPV6: {
		struct rte_ipv6_hdr *ipv6_hdr = rte_pktmbuf_mtod_offset(pkt,
			struct rte_ipv6_hdr *, parsed_len);
		int l3_len = ipv6_skip_exthdr(ipv6_hdr,
			pkt->data_len - parsed_len, &ctx->l4_proto);
		if (l3_len < 0) {
			G_LOG(NOTICE, "%s: Failed to parse IPv6 extension headers\n",
				__func__);
			return -1;
		}
		pkt->l3_len = l3_len;
		parsed_len += l3_len;
		ctx->fragmented = rte_ipv6_frag_get_ipv6_fragment_header(
			ipv6_hdr) != NULL;
		break;
	}

	default:
		G_LOG(ERR, "%s: Unknown L3 header %hu\n",
			__func__, packet->flow.proto);
		return -1;
	}

	pkt->l4_len = RTE_MIN(pkt->data_len - parsed_len,
		/* Maximum value that @pkt->l4_len can hold. */
		((1 << RTE_MBUF_L4_LEN_BITS) - 1));
	return 0;
}

int
gk_bpf_decide_pkt(struct gk_config *gk_conf, uint8_t program_index,
	struct flow_entry *fe, struct ipacket *packet, uint64_t now,
	uint64_t *p_bpf_ret)
{
	struct gk_bpf_pkt_frame frame = {
		.password = pkt_password,
		.fe = fe,
		.packet = packet,
		.gk_conf = gk_conf,
		.ready_to_tx = false,
		.ctx = {
			.now = now,
			.expire_at = fe->expire_at,
		},
	};
	const struct gk_bpf_flow_handler *handler =
		&gk_conf->flow_handlers[program_index];
	struct rte_bpf *bpf = handler->f_pkt;
	rte_bpf_jitted_func_t jit;

	if (unlikely(bpf == NULL)) {
		G_LOG(WARNING,
			"The BPF program at index %u does not have function pkt\n",
			program_index);
		return -EINVAL;
	}

	if (unlikely(parse_packet_further(packet, &frame.ctx) < 0))
		return -EINVAL;

	jit = handler->f_pkt_jit;
	*p_bpf_ret = likely(jit != NULL)
		? jit(&frame.ctx)
		: rte_bpf_exec(bpf, &frame.ctx);

	if (unlikely(*p_bpf_ret == GK_BPF_PKT_RET_FORWARD &&
			!frame.ready_to_tx)) {
		G_LOG(ERR,
			"The BPF program at index %u has a bug: it returned GK_BPF_PKT_RET_FORWARD without successfully calling gk_bpf_prep_for_tx()\n",
			program_index);
		return -EIO;
	}

	return 0;
}
