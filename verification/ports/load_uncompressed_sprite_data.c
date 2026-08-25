#include "port_state.h"

#define R_RAMB 0x4000u
#define S_SPRITE_BUFFER0 0xa000u
#define S_SPRITE_BUFFER1 0xa188u
#define S_SPRITE_BUFFER2 0xa310u
#define H_SPRITE_WIDTH 0xff8bu
#define H_SPRITE_HEIGHT 0xff8cu
#define H_SPRITE_OFFSET 0xff8du

void port_zero_sprite_buffer(struct cpu_register_state *, port_u8 *);
void port_align_sprite_data_centered(struct align_sprite_data_state *,
	port_u8 *);
void port_interlace_merge_sprite_buffers(struct cpu_register_state *,
	port_u8 *);

static void
load_sprite_set_pair(port_u8 *high, port_u8 *low, port_u16 value)
{
	*high = (port_u8)(value >> 8);
	*low = (port_u8)value;
}

static void
load_sprite_and(struct cpu_register_state *state, port_u8 value)
{
	state->a &= value;
	state->f = PORT_FLAG_H;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
}

static void
load_sprite_sub_b(struct cpu_register_state *state)
{
	port_u8 left = state->a;
	port_u8 right = state->b;

	state->a = (port_u8)(left - right);
	state->f = PORT_FLAG_N;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		state->f |= PORT_FLAG_H;
	if (left < right)
		state->f |= PORT_FLAG_C;
}

static void
load_sprite_inc_a(struct cpu_register_state *state)
{
	port_u8 old = state->a;

	state->a++;
	state->f &= PORT_FLAG_C;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0x0f)
		state->f |= PORT_FLAG_H;
}

static void
load_sprite_srl_a(struct cpu_register_state *state)
{
	port_u8 old = state->a;

	state->a >>= 1;
	state->f = 0;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
	if (old & 1)
		state->f |= PORT_FLAG_C;
}

static void
load_sprite_swap_a(struct cpu_register_state *state)
{
	state->a = (port_u8)((state->a << 4) | (state->a >> 4));
	state->f = state->a == 0 ? PORT_FLAG_Z : 0;
}

static void
load_sprite_add(struct cpu_register_state *state, port_u8 right)
{
	port_u8 left = state->a;
	port_u16 result = (port_u16)left + right;

	state->a = (port_u8)result;
	state->f = 0;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		state->f |= PORT_FLAG_H;
	if (result > 0xff)
		state->f |= PORT_FLAG_C;
}

static void
load_sprite_align(struct cpu_register_state *state, port_u8 *memory)
{
	struct align_sprite_data_state align;

	align.registers = *state;
	align.sprite_offset = memory[H_SPRITE_OFFSET];
	align.sprite_width = memory[H_SPRITE_WIDTH];
	align.sprite_height = memory[H_SPRITE_HEIGHT];
	port_align_sprite_data_centered(&align, memory);
	*state = align.registers;
}

/* Port of LoadUncompressedSpriteData in home/pics.asm. */
__attribute__((noinline, used)) void
port_load_uncompressed_sprite_data(struct cpu_register_state *state,
	port_u8 *memory)
{
	port_u16 output = (port_u16)(((port_u16)state->d << 8) | state->e);

	load_sprite_and(state, 0x0f);
	memory[H_SPRITE_WIDTH] = state->a;
	state->b = state->a;
	state->a = 7;
	load_sprite_sub_b(state);
	load_sprite_inc_a(state);
	load_sprite_srl_a(state);
	state->b = state->a;
	load_sprite_add(state, state->a);
	load_sprite_add(state, state->a);
	load_sprite_add(state, state->a);
	load_sprite_sub_b(state);
	memory[H_SPRITE_OFFSET] = state->a;

	state->a = state->c;
	load_sprite_swap_a(state);
	load_sprite_and(state, 0x0f);
	state->b = state->a;
	load_sprite_add(state, state->a);
	load_sprite_add(state, state->a);
	load_sprite_add(state, state->a);
	memory[H_SPRITE_HEIGHT] = state->a;
	state->a = 7;
	load_sprite_sub_b(state);
	state->b = state->a;
	state->a = memory[H_SPRITE_OFFSET];
	load_sprite_add(state, state->b);
	load_sprite_add(state, state->a);
	load_sprite_add(state, state->a);
	load_sprite_add(state, state->a);
	memory[H_SPRITE_OFFSET] = state->a;

	state->a = 0;
	state->f = PORT_FLAG_Z;
	memory[R_RAMB] = state->a;
	load_sprite_set_pair(&state->h, &state->l, S_SPRITE_BUFFER0);
	port_zero_sprite_buffer(state, memory);
	load_sprite_set_pair(&state->d, &state->e, S_SPRITE_BUFFER1);
	load_sprite_set_pair(&state->h, &state->l, S_SPRITE_BUFFER0);
	load_sprite_align(state, memory);
	load_sprite_set_pair(&state->h, &state->l, S_SPRITE_BUFFER1);
	port_zero_sprite_buffer(state, memory);
	load_sprite_set_pair(&state->d, &state->e, S_SPRITE_BUFFER2);
	load_sprite_set_pair(&state->h, &state->l, S_SPRITE_BUFFER1);
	load_sprite_align(state, memory);
	load_sprite_set_pair(&state->d, &state->e, output);
	port_interlace_merge_sprite_buffers(state, memory);
}
