#include "port_state.h"

#define W_SUBANIM_COUNTER 0xd087
#define W_SUBANIM_TRANSFORM 0xd08b
#define W_SUBANIM_ADDR_PTR 0xd094
#define W_SUBANIM_SUBENTRY_ADDR 0xd096
#define H_WHOSE_TURN 0xfff3

/* Port of LoadSubanimation's non-enemy, player's-turn path. */
__attribute__((noinline, used)) void
port_load_subanimation_normal(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 pointer = (port_u16)(((port_u16)memory[W_SUBANIM_ADDR_PTR + 1] << 8) |
		memory[W_SUBANIM_ADDR_PTR]);
	port_u16 subanimation = (port_u16)(((port_u16)memory[pointer + 1] << 8) |
		memory[pointer]);
	port_u8 packed = memory[subanimation];
	port_u16 subentry = (port_u16)(subanimation + 1);

	memory[W_SUBANIM_COUNTER] = packed & 0x1f;
	memory[W_SUBANIM_TRANSFORM] = 0;
	memory[W_SUBANIM_SUBENTRY_ADDR] = (port_u8)subentry;
	memory[W_SUBANIM_SUBENTRY_ADDR + 1] = (port_u8)(subentry >> 8);
	state->a = (port_u8)(subentry >> 8);
	state->b = 0;
	state->d = (port_u8)(subentry >> 8);
	state->e = (port_u8)subentry;
	state->h = (port_u8)(subentry >> 8);
	state->l = (port_u8)subentry;
	state->f = 0;
	(void)H_WHOSE_TURN;
}

#define SUBANIMTYPE_REVERSE 4u
#define SUBANIMTYPE_ENEMY 5u
#define SUBANIMTYPE_HFLIP 2u

static port_u8
load_subanimation_cp(port_u8 left, port_u8 right)
{
	port_u8 flags = PORT_FLAG_N;

	if (left == right)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (right & 0x0fu))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

static void
load_subanimation_add_hl(struct cpu_register_state *state,
	port_u16 left, port_u16 right)
{
	port_u16 result = (port_u16)(left + right);
	port_u8 flags = state->f & (PORT_FLAG_Z | PORT_FLAG_N);

	if ((left & 0x0fffu) + (right & 0x0fffu) > 0x0fffu)
		flags |= PORT_FLAG_H;
	if ((port_u32)left + right > 0xffffu)
		flags |= PORT_FLAG_C;
	state->f = flags;
	state->h = (port_u8)(result >> 8);
	state->l = (port_u8)result;
}

/* Complete port of LoadSubanimation in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_load_subanimation(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 pointer = (port_u16)(((port_u16)memory[W_SUBANIM_ADDR_PTR + 1] << 8) |
		memory[W_SUBANIM_ADDR_PTR]);
	port_u16 subanimation = (port_u16)(((port_u16)memory[pointer + 1] << 8) |
		memory[pointer]);
	port_u8 packed = memory[subanimation];
	port_u8 type = (port_u8)(packed >> 5);
	port_u8 counter = (port_u8)(packed & 0x1fu);
	port_u8 top_bits = (port_u8)(packed & 0xe0u);
	port_u8 transform;
	port_u16 subentry = (port_u16)(subanimation + 1u);
	port_u16 offset = 0;

	memory[W_SUBANIM_COUNTER] = counter;
	state->b = type == SUBANIMTYPE_ENEMY ? packed : top_bits;
	if (type == SUBANIMTYPE_ENEMY) {
		transform = memory[H_WHOSE_TURN] == 0
			? SUBANIMTYPE_HFLIP : 0;
	} else {
		transform = memory[H_WHOSE_TURN] == 0 ? 0 : type;
	}
	state->f = load_subanimation_cp(transform, SUBANIMTYPE_REVERSE);
	memory[W_SUBANIM_TRANSFORM] = transform;

	if (transform == SUBANIMTYPE_REVERSE) {
		port_u8 remaining = (port_u8)(counter - 1u);

		state->b = 0;
		state->c = 3;
		do {
			port_u8 before = remaining;
			load_subanimation_add_hl(state, offset, 3);
			offset = (port_u16)(((port_u16)state->h << 8) | state->l);
			remaining--;
			state->f = (state->f & PORT_FLAG_C) | PORT_FLAG_N;
			if (remaining == 0)
				state->f |= PORT_FLAG_Z;
			if ((before & 0x0fu) == 0)
				state->f |= PORT_FLAG_H;
		} while (remaining != 0);
	}

	state->d = (port_u8)(subentry >> 8);
	state->e = (port_u8)subentry;
	load_subanimation_add_hl(state, offset, subentry);
	memory[W_SUBANIM_SUBENTRY_ADDR] = state->l;
	memory[W_SUBANIM_SUBENTRY_ADDR + 1] = state->h;
	state->a = state->h;
}
