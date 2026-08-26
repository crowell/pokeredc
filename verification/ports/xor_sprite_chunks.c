#include "port_state.h"

#define W_SPRITE_CUR_POS_X 0xd0a1u
#define W_SPRITE_CUR_POS_Y 0xd0a2u
#define W_SPRITE_WIDTH 0xd0a3u
#define W_SPRITE_HEIGHT 0xd0a4u
#define W_SPRITE_LOAD_FLAGS 0xd0a9u
#define W_SPRITE_FLIPPED 0xd0aau
#define W_SPRITE_OUTPUT_PTR 0xd0adu
#define W_SPRITE_OUTPUT_PTR_CACHED 0xd0afu
#define NYBBLE_REVERSE_TABLE 0x2867u

void port_reset_sprite_buffer_pointers(struct register_memory_state *);
void port_sprite_differential_decode(struct cpu_register_state *, port_u8 *);
void port_reverse_nybble(struct computed_load_state *);

static port_u16
xor_sprite_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
xor_sprite_set_pair(port_u8 *high, port_u8 *low, port_u16 value)
{
	*high = (port_u8)(value >> 8);
	*low = (port_u8)value;
}

static void
xor_sprite_reset_pointers(struct cpu_register_state *state, port_u8 *memory)
{
	struct register_memory_state reset;

	reset.registers = *state;
	reset.memory[0] = memory[W_SPRITE_LOAD_FLAGS];
	reset.memory[1] = memory[W_SPRITE_OUTPUT_PTR];
	reset.memory[2] = memory[W_SPRITE_OUTPUT_PTR + 1];
	reset.memory[3] = memory[W_SPRITE_OUTPUT_PTR_CACHED];
	reset.memory[4] = memory[W_SPRITE_OUTPUT_PTR_CACHED + 1];
	port_reset_sprite_buffer_pointers(&reset);
	*state = reset.registers;
	memory[W_SPRITE_OUTPUT_PTR] = reset.memory[1];
	memory[W_SPRITE_OUTPUT_PTR + 1] = reset.memory[2];
	memory[W_SPRITE_OUTPUT_PTR_CACHED] = reset.memory[3];
	memory[W_SPRITE_OUTPUT_PTR_CACHED + 1] = reset.memory[4];
}

static void
xor_sprite_reverse_nybble(struct cpu_register_state *state, port_u8 *memory)
{
	struct computed_load_state reverse;

	reverse.registers = *state;
	reverse.fetched = memory[NYBBLE_REVERSE_TABLE + state->a];
	port_reverse_nybble(&reverse);
	*state = reverse.registers;
}

static void
xor_sprite_and(struct cpu_register_state *state, port_u8 value)
{
	state->a &= value;
	state->f = (port_u8)(PORT_FLAG_H |
		(state->a == 0 ? PORT_FLAG_Z : 0));
}

static void
xor_sprite_inc_a(struct cpu_register_state *state)
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
xor_sprite_add(struct cpu_register_state *state, port_u8 value)
{
	port_u8 old = state->a;
	port_u16 result = (port_u16)old + value;

	state->a = (port_u8)result;
	state->f = 0;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
	if ((old & 0x0f) + (value & 0x0f) > 0x0f)
		state->f |= PORT_FLAG_H;
	if (result > 0xff)
		state->f |= PORT_FLAG_C;
}

static void
xor_sprite_cp_b(struct cpu_register_state *state)
{
	port_u8 left = state->a;
	port_u8 right = state->b;

	state->f = PORT_FLAG_N;
	if (left == right)
		state->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		state->f |= PORT_FLAG_H;
	if (left < right)
		state->f |= PORT_FLAG_C;
}

/* Port of XorSpriteChunks in home/uncompress.asm. */
__attribute__((noinline, used)) void
port_xor_sprite_chunks(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 source;
	port_u16 destination;

	state->a = 0;
	state->f = PORT_FLAG_Z;
	memory[W_SPRITE_CUR_POS_X] = state->a;
	memory[W_SPRITE_CUR_POS_Y] = state->a;
	xor_sprite_reset_pointers(state, memory);
	state->a = memory[W_SPRITE_OUTPUT_PTR];
	state->l = state->a;
	state->a = memory[W_SPRITE_OUTPUT_PTR + 1];
	state->h = state->a;
	port_sprite_differential_decode(state, memory);
	xor_sprite_reset_pointers(state, memory);
	state->a = memory[W_SPRITE_OUTPUT_PTR];
	state->l = state->a;
	state->a = memory[W_SPRITE_OUTPUT_PTR + 1];
	state->h = state->a;
	state->a = memory[W_SPRITE_OUTPUT_PTR_CACHED];
	state->e = state->a;
	state->a = memory[W_SPRITE_OUTPUT_PTR_CACHED + 1];
	state->d = state->a;

	do {
		do {
			port_u16 saved_destination;

			state->a = memory[W_SPRITE_FLIPPED];
			xor_sprite_and(state, state->a);
			if (state->a != 0) {
				saved_destination = xor_sprite_pair(state->d,
					state->e);
				state->a = memory[saved_destination];
				state->b = state->a;
				state->a = (port_u8)((state->a << 4) |
					(state->a >> 4));
				state->f = state->a == 0 ? PORT_FLAG_Z : 0;
				xor_sprite_and(state, 0x0f);
				xor_sprite_reverse_nybble(state, memory);
				state->a = (port_u8)((state->a << 4) |
					(state->a >> 4));
				state->f = state->a == 0 ? PORT_FLAG_Z : 0;
				state->c = state->a;
				state->a = state->b;
				xor_sprite_and(state, 0x0f);
				xor_sprite_reverse_nybble(state, memory);
				state->a |= state->c;
				state->f = state->a == 0 ? PORT_FLAG_Z : 0;
				xor_sprite_set_pair(&state->d, &state->e,
					saved_destination);
				memory[saved_destination] = state->a;
			}

			source = xor_sprite_pair(state->h, state->l);
			state->a = memory[source++];
			xor_sprite_set_pair(&state->h, &state->l, source);
			state->b = state->a;
			destination = xor_sprite_pair(state->d, state->e);
			state->a = memory[destination];
			state->a ^= state->b;
			state->f = state->a == 0 ? PORT_FLAG_Z : 0;
			memory[destination++] = state->a;
			xor_sprite_set_pair(&state->d, &state->e, destination);
			state->a = memory[W_SPRITE_CUR_POS_Y];
			xor_sprite_inc_a(state);
			memory[W_SPRITE_CUR_POS_Y] = state->a;
			state->b = state->a;
			state->a = memory[W_SPRITE_HEIGHT];
			xor_sprite_cp_b(state);
		} while ((state->f & PORT_FLAG_Z) == 0);

		state->a = 0;
		state->f = PORT_FLAG_Z;
		memory[W_SPRITE_CUR_POS_Y] = state->a;
		state->a = memory[W_SPRITE_CUR_POS_X];
		xor_sprite_add(state, 8);
		memory[W_SPRITE_CUR_POS_X] = state->a;
		state->b = state->a;
		state->a = memory[W_SPRITE_WIDTH];
		xor_sprite_cp_b(state);
	} while ((state->f & PORT_FLAG_Z) == 0);

	state->a = 0;
	state->f = PORT_FLAG_Z;
	memory[W_SPRITE_CUR_POS_X] = state->a;
}
