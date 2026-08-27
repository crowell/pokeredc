#include "port_state.h"

#define W_SPRITE_CUR_POS_X 0xd0a1u
#define W_SPRITE_CUR_POS_Y 0xd0a2u
#define W_SPRITE_WIDTH 0xd0a3u
#define W_SPRITE_HEIGHT 0xd0a4u
#define W_SPRITE_FLIPPED 0xd0aau
#define W_SPRITE_OUTPUT_PTR 0xd0adu
#define W_SPRITE_OUTPUT_PTR_CACHED 0xd0afu
#define W_SPRITE_DECODE_TABLE0_PTR 0xd0b1u
#define W_SPRITE_DECODE_TABLE1_PTR 0xd0b3u
#define DECODE_NYBBLE0_TABLE 0x27a7u
#define DECODE_NYBBLE1_TABLE 0x27afu
#define DECODE_NYBBLE0_TABLE_FLIPPED 0x27b7u
#define DECODE_NYBBLE1_TABLE_FLIPPED 0x27bfu

void port_store_sprite_output_pointer(struct button_reset_state *);
void port_differential_decode_nybble(struct differential_decode_state *);

static port_u16
sprite_decode_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
sprite_decode_set_pair(port_u8 *high, port_u8 *low, port_u16 value)
{
	*high = (port_u8)(value >> 8);
	*low = (port_u8)value;
}

static void
sprite_decode_store_pointer(struct cpu_register_state *state,
	port_u8 *memory)
{
	struct button_reset_state pointer;

	pointer.registers = *state;
	port_store_sprite_output_pointer(&pointer);
	*state = pointer.registers;
	memory[W_SPRITE_OUTPUT_PTR] = pointer.memory[0];
	memory[W_SPRITE_OUTPUT_PTR_CACHED] = pointer.memory[1];
	memory[W_SPRITE_OUTPUT_PTR + 1] = pointer.memory[2];
	memory[W_SPRITE_OUTPUT_PTR_CACHED + 1] = pointer.memory[3];
}

static void
sprite_decode_nybble(struct cpu_register_state *state, port_u8 *memory)
{
	struct differential_decode_state decode;
	port_u8 encoded = state->a;
	port_u8 previous = state->e;
	port_u8 normal;
	port_u8 flipped;
	port_u8 flip_mask;
	port_u8 previous_mask;
	port_u8 decoded;

	decode.registers = *state;
	decode.flipped = memory[W_SPRITE_FLIPPED];
	decode.table0_low = memory[W_SPRITE_DECODE_TABLE0_PTR];
	decode.table0_high = memory[W_SPRITE_DECODE_TABLE0_PTR + 1];
	decode.table1_low = memory[W_SPRITE_DECODE_TABLE1_PTR];
	decode.table1_high = memory[W_SPRITE_DECODE_TABLE1_PTR + 1];
	normal = (port_u8)((encoded & 1u) ^
		((port_u8)-(port_u8)((encoded >> 1) & 1u) & 3u) ^
		((port_u8)-(port_u8)((encoded >> 2) & 1u) & 7u) ^
		((port_u8)-(port_u8)((encoded >> 3) & 1u) & 0x0fu));
	flipped = (port_u8)(
		((port_u8)-(port_u8)(encoded & 1u) & 8u) ^
		((port_u8)-(port_u8)((encoded >> 1) & 1u) & 0x0cu) ^
		((port_u8)-(port_u8)((encoded >> 2) & 1u) & 0x0eu) ^
		((port_u8)-(port_u8)((encoded >> 3) & 1u) & 0x0fu));
	flip_mask = (port_u8)-(port_u8)(decode.flipped != 0);
	decoded = (port_u8)((normal & (port_u8)~flip_mask) |
		(flipped & flip_mask));
	previous_mask = (port_u8)((1u & (port_u8)~flip_mask) |
		(8u & flip_mask));
	decoded ^= (port_u8)-(port_u8)((previous & previous_mask) != 0) &
		0x0fu;
	decode.fetched = (port_u8)((decoded << 4) | decoded);
	port_differential_decode_nybble(&decode);
	*state = decode.registers;
}

static void
sprite_decode_and(struct cpu_register_state *state, port_u8 value)
{
	state->a &= value;
	state->f = (port_u8)(PORT_FLAG_H |
		(state->a == 0 ? PORT_FLAG_Z : 0));
}

static void
sprite_decode_add(struct cpu_register_state *state, port_u8 value)
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
sprite_decode_cp_b(struct cpu_register_state *state)
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

static void
sprite_decode_inc_a(struct cpu_register_state *state)
{
	port_u8 old = state->a;

	state->a++;
	state->f &= PORT_FLAG_C;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0x0f)
		state->f |= PORT_FLAG_H;
}

/* Port of SpriteDifferentialDecode in home/uncompress.asm. */
__attribute__((noinline, used)) void
port_sprite_differential_decode(struct cpu_register_state *state,
	port_u8 *memory)
{
	port_u16 table0;
	port_u16 table1;

	state->a = 0;
	state->f = PORT_FLAG_Z;
	memory[W_SPRITE_CUR_POS_X] = state->a;
	memory[W_SPRITE_CUR_POS_Y] = state->a;
	sprite_decode_store_pointer(state, memory);
	state->a = memory[W_SPRITE_FLIPPED];
	state->f = PORT_FLAG_H;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
	if (state->a == 0) {
		table0 = DECODE_NYBBLE0_TABLE;
		table1 = DECODE_NYBBLE1_TABLE;
	} else {
		table0 = DECODE_NYBBLE0_TABLE_FLIPPED;
		table1 = DECODE_NYBBLE1_TABLE_FLIPPED;
	}
	sprite_decode_set_pair(&state->h, &state->l, table0);
	sprite_decode_set_pair(&state->d, &state->e, table1);
	state->a = state->l;
	memory[W_SPRITE_DECODE_TABLE0_PTR] = state->a;
	state->a = state->h;
	memory[W_SPRITE_DECODE_TABLE0_PTR + 1] = state->a;
	state->a = state->e;
	memory[W_SPRITE_DECODE_TABLE1_PTR] = state->a;
	state->a = state->d;
	memory[W_SPRITE_DECODE_TABLE1_PTR + 1] = state->a;
	state->e = 0;

	do {
		do {
			port_u16 pointer = sprite_decode_pair(
				memory[W_SPRITE_OUTPUT_PTR + 1],
				memory[W_SPRITE_OUTPUT_PTR]);

			sprite_decode_set_pair(&state->h, &state->l, pointer);
			state->a = memory[pointer];
			state->b = state->a;
			state->a = (port_u8)((state->a << 4) |
				(state->a >> 4));
			state->f = state->a == 0 ? PORT_FLAG_Z : 0;
			sprite_decode_and(state, 0x0f);
			sprite_decode_nybble(state, memory);
			state->a = (port_u8)((state->a << 4) |
				(state->a >> 4));
			state->f = state->a == 0 ? PORT_FLAG_Z : 0;
			state->d = state->a;
			state->a = state->b;
			sprite_decode_and(state, 0x0f);
			sprite_decode_nybble(state, memory);
			state->a |= state->d;
			state->f = state->a == 0 ? PORT_FLAG_Z : 0;
			state->b = state->a;
			pointer = sprite_decode_pair(
				memory[W_SPRITE_OUTPUT_PTR + 1],
				memory[W_SPRITE_OUTPUT_PTR]);
			sprite_decode_set_pair(&state->h, &state->l, pointer);
			state->a = state->b;
			memory[pointer] = state->a;
			state->a = memory[W_SPRITE_HEIGHT];
			sprite_decode_add(state, state->l);
			if (state->f & PORT_FLAG_C) {
				port_u8 old = state->h;

				state->h++;
				state->f &= PORT_FLAG_C;
				if (state->h == 0)
					state->f |= PORT_FLAG_Z;
				if ((old & 0x0f) == 0x0f)
					state->f |= PORT_FLAG_H;
			}
			memory[W_SPRITE_OUTPUT_PTR] = state->a;
			state->a = state->h;
			memory[W_SPRITE_OUTPUT_PTR + 1] = state->a;
			state->a = memory[W_SPRITE_CUR_POS_X];
			sprite_decode_add(state, 8);
			memory[W_SPRITE_CUR_POS_X] = state->a;
			state->b = state->a;
			state->a = memory[W_SPRITE_WIDTH];
			sprite_decode_cp_b(state);
		} while ((state->f & PORT_FLAG_Z) == 0);

		state->a = 0;
		state->f = PORT_FLAG_Z;
		state->e = state->a;
		memory[W_SPRITE_CUR_POS_X] = state->a;
		state->a = memory[W_SPRITE_CUR_POS_Y];
		sprite_decode_inc_a(state);
		memory[W_SPRITE_CUR_POS_Y] = state->a;
		state->b = state->a;
		state->a = memory[W_SPRITE_HEIGHT];
		sprite_decode_cp_b(state);
		if (state->f & PORT_FLAG_Z)
			break;
		state->l = memory[W_SPRITE_OUTPUT_PTR_CACHED];
		state->h = memory[W_SPRITE_OUTPUT_PTR_CACHED + 1];
		{
			port_u16 pointer = (port_u16)(
				sprite_decode_pair(state->h, state->l) + 1);

			sprite_decode_set_pair(&state->h, &state->l, pointer);
		}
		sprite_decode_store_pointer(state, memory);
	} while (1);

	state->a = 0;
	state->f = PORT_FLAG_Z;
	memory[W_SPRITE_CUR_POS_Y] = state->a;
}
