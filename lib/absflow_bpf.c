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

#include <rte_bpf.h>

#include "gatekeeper_main.h"
#include "gatekeeper_absflow.h"

/*
 * The following links are helpful references to BPF instructions:
 *
 * 1. Code example in DPDK: dependencies/dpdk/app/test/test_bpf.c
 * 2. Essential definitions: dependencies/dpdk/lib/librte_bpf/bpf_def.h
 * 3. Summary of all BPF instructions:
 *	https://github.com/iovisor/bpf-docs/blob/master/eBPF.md
 * 4. The official documentation for the BPF instruction set:
 *	https://www.kernel.org/doc/Documentation/networking/filter.txt
 */

/* BPF_MAXINSNS is present in <linux/bpf_common.h>, but not in <rte_bpf.h>. */
#ifndef BPF_MAXINSNS
#define BPF_MAXINSNS 4096
#endif

struct absflow_bfp_prog {
	struct ebpf_insn prog[BPF_MAXINSNS];
	uint16_t         num_ins;
};

struct register_tracker {
	struct register_state {
		uint8_t reg;

		bool has_value;
		enum ft_source source;

		/* Parameters for FTS_*_HEADER *only*. */
		uint16_t hdr_offset;
		uint16_t hdr_length;

		uint64_t mask;
	} regs[10];

	/*
	 * The registers from index 0 to (@num_free_regs - 1) are available
	 * for processing.
	 */
	uint8_t num_regs;

	/* Number of registers in use. */
	uint8_t used_regs;

	/*
	 * Registers where pointers to L3 header, L4 header, and
	 * BPF context are found.
	 *
	 * If a given pointer is not available, the value is -1.
	 */
	int8_t l3_hdr_reg;
	int8_t l4_hdr_reg;
	int8_t ctx_reg;
};

static void
init_reg_tracker(struct register_tracker *tracker)
{
	unsigned int i;

	memset(tracker, 0, sizeof(*tracker));

	RTE_BUILD_BUG_ON(EBPF_REG_0 + RTE_DIM(tracker->regs) - 1 > EBPF_REG_9);
	for (i = 0; i < RTE_DIM(tracker->regs); i++)
		tracker->regs[i].reg = EBPF_REG_0 + i;

	tracker->num_regs = RTE_DIM(tracker->regs);
	tracker->l3_hdr_reg = -1;
	tracker->l4_hdr_reg = -1;
	tracker->ctx_reg = -1;
}

static struct register_state *
get_reg(struct register_tracker *tracker)
{
	if (unlikely(tracker->used_regs >= tracker->num_regs)) {
		/*
		 * If this ever becomes an issue, a solution is to use
		 * the stack of BPF.
		 */
		G_LOG(ERR, "%s(): not enough registers in BPF\n", __func__);
		return NULL;
	}
	return &tracker->regs[tracker->used_regs++];
}

static inline void
clear_reg(struct register_state *state)
{
	state->has_value = false;
}

static int
put_reg(struct register_tracker *tracker, struct register_state *state)
{
	if (unlikely(tracker->used_regs == 0)) {
		G_LOG(ERR, "%s(): bug: there is no register to put back\n",
			__func__);
		return -EINVAL;
	}
	if (unlikely(state != &tracker->regs[tracker->used_regs - 1])) {
		G_LOG(ERR, "%s(): bug: cannot put register %i backk\n",
			__func__, state->reg);
		return -ENOTSUP;
	}
	clear_reg(state);
	tracker->used_regs--;
	return 0;
}

#define REQ_L2_HEADER (1 << 0)
#define REQ_L3_HEADER (1 << 1)
#define REQ_L4_HEADER (1 << 2)
#define REQ_CTX       (1 << 3)

/*
 * Return a bit set with the following information:
 * REQ_L2_HEADER: The pointer to the L2 header is required.
 * REQ_L3_HEADER: The pointer to the L3 header is required.
 * REQ_L4_HEADER: The pointer to the L4 header is required.
 * REQ_CTX:       The pointer to the BPF context is required.
 */
static uint32_t
required_poiters(const struct flow_tree_node *node)
{
	uint32_t ret = 0;

	if (unlikely(node == NULL))
		return ret;

	switch (node->source) {
	case FTS_L2_HEADER:
		ret |= REQ_L2_HEADER;
		break;
	case FTS_L3_HEADER:
		ret |= REQ_L3_HEADER;
		break;
	case FTS_L4_HEADER:
		ret |= REQ_L4_HEADER;
		break;
	case FTS_L3_PROTO:
	case FTS_L4_PROTO:
	case FTS_L4_LEN:
	case FTS_L4_FRAGMENTED:
		ret |= REQ_CTX;
		break;
	};

	return ret | required_poiters(node->and_branch) |
		required_poiters(node->or_branch);
}

static int
add_instructions(struct absflow_bfp_prog *prog, const struct ebpf_insn *ins,
	unsigned int num_ins)
{
	if (unlikely(prog->num_ins + num_ins > RTE_DIM(prog->prog))) {
		G_LOG(ERR, "%s(): BPF is too big\n", __func__);
		return -ENOENT;
	}
	rte_memcpy(&prog->prog[prog->num_ins], ins, num_ins * sizeof(*ins));
	prog->num_ins += num_ins;
	return 0;
}

static int
copy_reg(struct absflow_bfp_prog *prog, uint8_t from, uint8_t to)
{
	const struct ebpf_insn ins[] = {
		{
			.code = EBPF_ALU64 | EBPF_MOV | BPF_X,
			.dst_reg = to,
			.src_reg = from,
		},
	};
	return add_instructions(prog, ins, RTE_DIM(ins));
}

#define XSYM_L3_HEADER_INDEX (0)
#define XSYM_L4_HEADER_INDEX (1)

static int
get_pointer(struct absflow_bfp_prog *prog, uint8_t dst, uint8_t call_idx,
	uint8_t ctx_reg, bool *pctx_at_reg1)
{
	const struct ebpf_insn ins[] = {
		{
			.code = BPF_JMP | EBPF_CALL,
			.imm = call_idx,
		},
		{
			.code = EBPF_ALU64 | EBPF_MOV | BPF_X,
			.dst_reg = dst,
			.src_reg = EBPF_REG_0,
		},
	};

	/* Put BPF context in register 1 if needed. */
	if (!*pctx_at_reg1) {
		int ret = copy_reg(prog, ctx_reg, EBPF_REG_1);
		if (unlikely(ret < 0))
			return ret;
	} else
		*pctx_at_reg1 = false;

	return add_instructions(prog, ins, RTE_DIM(ins));
}

static inline uint8_t
reserve_last_register(struct register_tracker *tracker)
{
	return tracker->regs[--tracker->num_regs].reg;
}

static int
allocate_pointers(struct register_tracker *tracker,
	struct absflow_bfp_prog *prog, const struct flow_tree_node *root,
	bool ctx_at_reg1)
{
	uint32_t pointers = required_poiters(root);
	uint8_t ctx_reg, ctx_reg_idx;
	int ret;

	if (unlikely(pointers & REQ_L2_HEADER)) {
		G_LOG(ERR, "%s(): L2 header is not supported\n", __func__);
		return -ENOTSUP;
	}

	ctx_reg_idx = tracker->num_regs - !!(pointers & REQ_L3_HEADER) -
		!!(pointers & REQ_L4_HEADER) - 1;
	ctx_reg = tracker->regs[ctx_reg_idx].reg;
	/* Save pointer to BPF context in register @ctx_reg. */
	ret = copy_reg(prog, EBPF_REG_1, ctx_reg);
	if (unlikely(ret < 0))
		return ret;

	if (pointers & REQ_L4_HEADER) {
		tracker->l4_hdr_reg = reserve_last_register(tracker);
		ret = get_pointer(prog, tracker->l4_hdr_reg,
			XSYM_L4_HEADER_INDEX, ctx_reg, &ctx_at_reg1);
		if (unlikely(ret < 0))
			return ret;
	}

	if (pointers & REQ_L3_HEADER) {
		tracker->l3_hdr_reg = reserve_last_register(tracker);
		ret = get_pointer(prog, tracker->l3_hdr_reg,
			XSYM_L3_HEADER_INDEX, ctx_reg, &ctx_at_reg1);
		if (unlikely(ret < 0))
			return ret;
	}


	if (pointers & REQ_CTX) {
		tracker->ctx_reg = reserve_last_register(tracker);
		if (unlikely(tracker->num_regs != ctx_reg_idx ||
				tracker->ctx_reg != ctx_reg)) {
			G_LOG(CRIT, "%s(): bug: tracker->num_regs=%i != ctx_reg_idx=%i || tracker->ctx_reg=%i != ctx_reg=%i\n",
				__func__, tracker->num_regs, ctx_reg_idx,
				tracker->ctx_reg, ctx_reg);
			return -EFAULT;
		}
	}

	return 0;
}

static bool
has_same_input(const struct register_state *state,
	const struct flow_tree_node *next_node)
{
	if (!state->has_value || next_node == NULL ||
		state->source != next_node->source)
	       return false;

	switch (state->source) {
	case FTS_L2_HEADER:
	case FTS_L3_HEADER:
	case FTS_L4_HEADER:
		return state->hdr_offset == next_node->hdr_offset &&
			state->hdr_length == next_node->hdr_length &&
			state->mask == next_node->mask;

	case FTS_L3_PROTO:
	case FTS_L4_PROTO:
	case FTS_L4_LEN:
	case FTS_L4_FRAGMENTED:
		return state->mask == next_node->mask;
	}

	return true;
}

static int
mask32_reg(struct absflow_bfp_prog *prog, uint8_t reg, rte_be32_t be_mask)
{
	const struct ebpf_insn ins[] = {
		{
			.code = BPF_ALU | BPF_AND | BPF_K,
			.dst_reg = reg,
			.imm = be_mask,
		},
	};
	return add_instructions(prog, ins, RTE_DIM(ins));
}

static int
load_reg64(struct absflow_bfp_prog *prog, uint8_t reg,
	rte_be32_t high_be, rte_be32_t low_be)
{
	const struct ebpf_insn set_high_ins[] = {
		{
			.code = BPF_ALU | EBPF_MOV | BPF_K,
			.dst_reg = reg,
			.imm = high_be,
		},
		{
			.code = EBPF_ALU64 | BPF_LSH | BPF_K,
			.dst_reg = reg,
			.imm = 32,
		},
	};
	const struct ebpf_insn set_low_ins[] = {
		{
			.code = EBPF_ALU64 | BPF_OR | BPF_K,
			.dst_reg = reg,
			.src_reg = low_be,
		},
	};
	int ret = add_instructions(prog, set_high_ins, RTE_DIM(set_high_ins));
	if (unlikely(ret < 0))
		return ret;

	if (low_be != 0) {
		return add_instructions(prog, set_low_ins,
			RTE_DIM(set_low_ins));
	}

	return 0;
}

static int
mask64_reg(struct absflow_bfp_prog *prog, uint8_t reg, uint8_t tmp_reg,
	rte_be32_t high_be_mask, rte_be32_t low_be_mask)
{
	const struct ebpf_insn mask_ins[] = {
		{
			.code = EBPF_ALU64 | BPF_AND | BPF_X,
			.dst_reg = reg,
			.src_reg = tmp_reg,
		},
	};

	int ret = load_reg64(prog, tmp_reg, high_be_mask, low_be_mask);
	if (unlikely(ret < 0))
		return ret;

	return add_instructions(prog, mask_ins, RTE_DIM(mask_ins));
}

static inline void
break_64(uint64_t value, uint32_t *phigh, uint32_t *plow)
{
	*phigh = value >> 32;
	*plow = value & 0xFFFFFFFF;
}

static int
mask_reg(struct register_tracker *tracker, struct absflow_bfp_prog *prog,
	uint8_t reg, uint16_t length, uint64_t mask)
{
	if (mask == (typeof(mask))-1)
		return 0;

	switch (length) {
	case 1:
		if (mask == 0xFF)
			return 0;
		return mask32_reg(prog, reg, mask);
	case 2:
		if (mask == 0xFFFF)
			return 0;
		return mask32_reg(prog, reg, rte_cpu_to_be_16(mask));
	case 4:
		if (mask == 0xFFFFFFFF)
			return 0;
		return mask32_reg(prog, reg, rte_cpu_to_be_32(mask));

	case 8: {
		rte_be32_t high_be_mask, low_be_mask;
		struct register_state *state;
		int ret, ret2;

		break_64(rte_cpu_to_be_64(mask), &high_be_mask, &low_be_mask);
		if (high_be_mask == 0) {
			if (low_be_mask == 0xFFFFFFFF)
				return 0;
			return mask32_reg(prog, reg, low_be_mask);
		}

		state = get_reg(tracker);
		if (unlikely(state == NULL))
			return -ENOENT;
		ret = mask64_reg(prog, reg, state->reg,
			high_be_mask, low_be_mask);
		ret2 = put_reg(tracker, state);
		if (unlikely(ret2 < 0))
			return ret2;
		return ret;
	}

	default:
		return -ENOTSUP;
	}
}

static int
bpf_opcode_size(uint16_t size)
{
	switch (size) {
	case 1: return BPF_B;
	case 2: return BPF_H;
	case 4: return BPF_W;
	case 8: return EBPF_DW;
	default:
		return -EINVAL;
	}
}

static int
get_input(struct register_tracker *tracker, struct absflow_bfp_prog *prog,
	const struct register_state *state, uint8_t ptr_reg, uint16_t offset,
	uint16_t length, uint64_t mask)
{
	int ret;
	int bpf_opsz = bpf_opcode_size(length);
	const struct ebpf_insn ins[] = {
		{
			.code = BPF_LDX | BPF_MEM | bpf_opsz,
			.dst_reg = state->reg,
			.src_reg = ptr_reg,
			.off = offset,
		},
	};

	if (unlikely(bpf_opsz < 0)) {
		G_LOG(ERR, "%s(): length=%i is not supported\n",
			__func__, length);
		return -ENOTSUP;
	}
	ret = add_instructions(prog, ins, RTE_DIM(ins));
	if (unlikely(ret < 0))
		return ret;

	return mask_reg(tracker, prog, state->reg, length, mask);
}

static void
update_register(struct register_state *state, const struct flow_tree_node *node)
{
	state->has_value = true;
	state->source = node->source;

	/*
	 * These fields may be junk, but copying a little bit of junk is easier
	 * than adding a switch..case to avoid copying junk.
	 */
	state->hdr_offset = node->hdr_offset;
	state->hdr_length = node->hdr_length;

	state->mask = node->mask;
}

#define fieldsizeof(type, member) sizeof(((type *)0)->member)

#define FIELD_DESC(type, member) offsetof(type, member), \
	fieldsizeof(type, member)

struct absflow_bpf_ctx {
	uint16_t l3_proto;
	uint16_t l4_proto;
	uint16_t l4_len;
	bool     l4_fragmented;
};

static int
compile_input(struct register_tracker *tracker, struct absflow_bfp_prog *prog,
	const struct flow_tree_node *node, struct register_state *state)
{
	int ret = -ENOTSUP;

	switch (node->source) {
	case FTS_L2_HEADER:
		break;

	case FTS_L3_HEADER:
		ret = get_input(tracker, prog, state, tracker->l3_hdr_reg,
			node->hdr_offset, node->hdr_length, node->mask);
		break;

	case FTS_L4_HEADER:
		ret = get_input(tracker, prog, state, tracker->l4_hdr_reg,
			node->hdr_offset, node->hdr_length, node->mask);
		break;

	case FTS_L3_PROTO:
		ret = get_input(tracker, prog, state, tracker->ctx_reg,
			FIELD_DESC(struct absflow_bpf_ctx, l3_proto),
			node->mask);
		break;

	case FTS_L4_PROTO:
		ret = get_input(tracker, prog, state, tracker->ctx_reg,
			FIELD_DESC(struct absflow_bpf_ctx, l4_proto),
			node->mask);
		break;

	case FTS_L4_LEN:
		ret = get_input(tracker, prog, state, tracker->ctx_reg,
			FIELD_DESC(struct absflow_bpf_ctx, l4_len),
			node->mask);
		break;

	case FTS_L4_FRAGMENTED:
		ret = get_input(tracker, prog, state, tracker->ctx_reg,
			FIELD_DESC(struct absflow_bpf_ctx, l4_fragmented),
			node->mask);
		break;
	}

	if (unlikely(ret < 0))
		return ret;

	update_register(state, node);
	return 0;
}

static int
return_class(struct absflow_bfp_prog *prog, uint32_t flow_id)
{
	const struct ebpf_insn ins[] = {
		{
			.code = BPF_ALU | EBPF_MOV | BPF_K,
			.dst_reg = EBPF_REG_0,
			.imm = flow_id,
		},
		{
			.code = BPF_JMP | EBPF_EXIT,
		},
	};
	return add_instructions(prog, ins, RTE_DIM(ins));
}

static int
add_jmp_instruction(struct absflow_bfp_prog *prog, struct ebpf_insn jmp_ins)
{
	int jmp_idx = prog->num_ins;
	int ret = add_instructions(prog, &jmp_ins, 1);
	if (unlikely(ret < 0))
		return ret;
	return jmp_idx;
}

static int
add_jump32(struct absflow_bfp_prog *prog, uint8_t reg, uint32_t value)
{
	const struct ebpf_insn jmp_ins = {
		.code = BPF_JMP | EBPF_JNE | BPF_K,
		.dst_reg = reg,
		/* Leave .off blank. */
		.imm = value,
	};
	return add_jmp_instruction(prog, jmp_ins);
}

static int
add_jump64(struct absflow_bfp_prog *prog, uint8_t reg1, uint8_t reg2)
{
	const struct ebpf_insn jmp_ins = {
		.code = BPF_JMP | EBPF_JNE | BPF_X,
		.dst_reg = reg1,
		.src_reg = reg2,
		/* Leave .off blank. */
	};
	return add_jmp_instruction(prog, jmp_ins);
}

static int
add_jump(struct register_tracker *tracker, struct absflow_bfp_prog *prog,
	const struct register_state *state, uint64_t value)
{
	rte_be32_t high_be_value, low_be_value;
	struct register_state *tmp_state;
	int ret, ret2;

	break_64(rte_cpu_to_be_64(value), &high_be_value, &low_be_value);
	if (likely(high_be_value == 0))
		return add_jump32(prog, state->reg, low_be_value);

	tmp_state = get_reg(tracker);
	if (unlikely(tmp_state == NULL))
		return -ENOENT;
	ret = load_reg64(prog, tmp_state->reg, high_be_value, low_be_value);
	if (unlikely(ret < 0))
		return ret;
	ret = add_jump64(prog, state->reg, tmp_state->reg);
	ret2 = put_reg(tracker, tmp_state);
	if (unlikely(ret2 < 0))
		return ret2;
	return ret;
}

static int
compile_node(struct register_tracker *tracker, struct absflow_bfp_prog *prog,
	const struct flow_tree_node *node, struct register_state *state,
	bool is_root)
{
	uint16_t jmp_idx;
	int ret;

	if (unlikely(node == NULL)) {
		if (unlikely(is_root)) {
			/* Return unclassified packet. */
			return return_class(prog,
				GATEKEEPER_ABSFLOW_INVALID_FLOWID);
		}
		return 0;
	}

	if (!has_same_input(state, node)) {
		/* The input of @node is NOT already in register @state->reg. */
		ret = compile_input(tracker, prog, node, state);
		if (unlikely(ret < 0))
			return ret;
	}

	ret = add_jump(tracker, prog, state, node->value);
	if (unlikely(ret < 0))
		return ret;
	jmp_idx = ret;

	if (node->and_branch != NULL) {
		struct register_state *next_state;

		if (has_same_input(state, node->or_branch)) {
			/* Preserve register for next or-branch. */
			next_state = get_reg(tracker);
			if (unlikely(next_state == NULL))
				return -ENOENT;
		} else
			next_state = state;

		ret = compile_node(tracker, prog, node->and_branch, next_state,
			false);
		if (unlikely(ret < 0))
			return ret;

		if (state != next_state) {
			ret = put_reg(tracker, next_state);
			if (unlikely(ret < 0))
				return ret;
		} else {
			/*
			 * @state must be cleared because the rest of
			 * the BPF code may be reached without going through
			 * the if-statement(s) of @node->and_branch.
			 */
			clear_reg(state);
		}
	}

	if (node->has_flow_id) {
		ret = return_class(prog, node->flow_id);
		if (unlikely(ret < 0))
			return ret;
	}

	/* Set jump destination. */
	prog->prog[jmp_idx].off = prog->num_ins - jmp_idx;

	return compile_node(tracker, prog, node->or_branch, state, is_root);
}

static int
compile_prog(struct absflow_bfp_prog *prog, const struct flow_tree_node *root)
{
	struct register_tracker tracker;
	struct register_state *state;
	int ret;

	init_reg_tracker(&tracker);
	ret = allocate_pointers(&tracker, prog, root, true);
	if (unlikely(ret < 0))
		return ret;

	state = get_reg(&tracker);
	if (unlikely(state == NULL))
		return -ENOENT;

	return compile_node(&tracker, prog, root, state, true);

	/*
	 * There is no need to put_reg(&tracker, state) because
	 * @tracker is going out of scope.
	 */
}

struct absflow_bpf_frame {
	uint64_t               password;
	const struct absflow_packet  *info;
	struct absflow_bpf_ctx ctx;
};

static const uint64_t frame_password = 0x63a56f60ed704877;

static struct absflow_bpf_frame *
ctx_to_frame(struct absflow_bpf_ctx *ctx)
{
	struct absflow_bpf_frame *frame;

	if (unlikely(ctx == NULL))
		return NULL;

	frame = container_of(ctx, struct absflow_bpf_frame, ctx);
	if (unlikely(frame->password != frame_password)) {
		G_LOG(WARNING, "%s(): password violation\n", __func__);
		return NULL;
	}

	return frame;
}

static void *
xsym_l3_header(struct absflow_bpf_ctx *ctx)
{
	struct absflow_bpf_frame *frame = ctx_to_frame(ctx);
	if (unlikely(frame == NULL))
		return NULL;
	return frame->info->l3_hdr;
}

static void *
xsym_l4_header(struct absflow_bpf_ctx *ctx)
{
	struct absflow_bpf_frame *frame = ctx_to_frame(ctx);
	if (unlikely(frame == NULL))
		return NULL;
	return frame->info->l4_hdr;
}

static int
load_prog(struct absflow_execution *exec, struct absflow_bfp_prog *prog)
{
	const struct rte_bpf_xsym xsyms[] = {
		[XSYM_L3_HEADER_INDEX] = {
			.name = "l3_header",
			.type = RTE_BPF_XTYPE_FUNC,
			.func = {
				.val = (void *)xsym_l3_header,
				.nb_args = 1,
				.args = {
					[0] = {
						.type = RTE_BPF_ARG_PTR,
						.size = sizeof(
							struct absflow_bpf_ctx),
					},
				},
				.ret = {
					.type = RTE_BPF_ARG_PTR,
					/* Limited access to the header */
					.size = 64,
				},
			},

		},
		[XSYM_L4_HEADER_INDEX]= {
			.name = "l4_header",
			.type = RTE_BPF_XTYPE_FUNC,
			.func = {
				.val = (void *)xsym_l4_header,
				.nb_args = 1,
				.args = {
					[0] = {
						.type = RTE_BPF_ARG_PTR,
						.size = sizeof(
							struct absflow_bpf_ctx),
					},
				},
				.ret = {
					.type = RTE_BPF_ARG_PTR,
					/* Limited access to the header */
					.size = 64,
				},
			},

		},
	};
	const struct rte_bpf_prm prm = {
		.ins = prog->prog,
		.nb_ins = prog->num_ins,
		.xsym = xsyms,
		.nb_xsym = RTE_DIM(xsyms),
		.prog_arg = {
			.type = RTE_BPF_ARG_PTR,
			.size = sizeof(struct absflow_bpf_ctx),
		},
	};
	struct rte_bpf_jit jit;
	int ret;

	struct rte_bpf *bpf = rte_bpf_load(&prm);
	if (unlikely(bpf == NULL)) {
		ret = -rte_errno;
		G_LOG(ERR, "%s(): failed to load BPF (errno=%i): %s\n",
			__func__, rte_errno, rte_strerror(rte_errno));
		return ret;
	}

	ret = rte_bpf_get_jit(bpf, &jit);
	if (unlikely(ret < 0)) {
		if (unlikely(ret != -ENOTSUP)) {
			G_LOG(ERR, "%s(): failed to JIT BPF (errno=%i): %s\n",
				__func__, -ret, strerror(-ret));
			return ret;
		}
		G_LOG(INFO, "%s(): BPF JIT is not available\n", __func__);
	}

	exec->f_class = bpf;
	exec->f_class_jit = jit.func;
	return 0;
}

int
absflow_enable_exec(struct absflow_execution *exec,
	const struct flow_tree_node *root)
{
	struct absflow_bfp_prog prog = {};

	int ret = compile_prog(&prog, root);
	if (unlikely(ret < 0))
		return ret;
	/* TODO Do we need this log? Does the load already provide it? */
	G_LOG(INFO, "%s(): %u instructions\n", __func__, prog.num_ins);

	return load_prog(exec, &prog);
}

void
absflow_free_exec(struct absflow_execution *exec)
{
	rte_bpf_destroy(exec->f_class);
	exec->f_class = NULL;
	exec->f_class_jit = NULL;
}

unsigned int
absflow_classify_packet(const struct absflow_execution *exec,
	const struct absflow_packet *info)
{
	struct absflow_bpf_frame frame = {
		.password = frame_password,
		.info = info,
		.ctx = {
			.l3_proto = info->l3_proto,
			.l4_proto = info->l4_proto,
			.l4_len = info->l4_len,
			.l4_fragmented = info->l4_fragmented,
		},
	};
	struct rte_bpf *bpf;

	rte_bpf_jitted_func_t jit = exec->f_class_jit;
	if (likely(jit != NULL))
		return jit(&frame.ctx);

	bpf = exec->f_class;
	if (unlikely(bpf == NULL)) {
		G_LOG(WARNING, "%s(): there is no BPF\n", __func__);
		/* Unclassified. */
		return GATEKEEPER_ABSFLOW_INVALID_FLOWID;
	}

	return rte_bpf_exec(bpf, &frame.ctx);
}
