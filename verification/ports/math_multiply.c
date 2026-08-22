#include "port_state.h"

/*
 * Full port of Multiply in home/math.asm, including the complete callfar
 * Bankswitch dispatch into _Multiply in engine/math/multiply_divide.asm and
 * the bank restore on the way out.
 */

static void
math_multiply_add(struct cpu_register_state *registers, port_u8 right,
	port_u8 with_carry)
{
	port_u8 left = registers->a;
	port_u8 carry = with_carry && (registers->f & PORT_FLAG_C);
	port_u16 wide = (port_u16)left + right + carry;
	port_u8 result = (port_u8)wide;

	registers->a = result;
	registers->f = 0;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) + carry > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xff)
		registers->f |= PORT_FLAG_C;
}

static void
math_multiply_shift_left(struct cpu_register_state *registers, port_u8 rotate)
{
	port_u8 value = registers->a;
	port_u8 carry = rotate && (registers->f & PORT_FLAG_C);

	registers->a = (port_u8)((value << 1) | carry);
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if (value & 0x80)
		registers->f |= PORT_FLAG_C;
}

/* Port of the _Multiply body in engine/math/multiply_divide.asm. */
static void
math_multiply_body(struct math_multiply_state *state)
{
	port_u8 index;

	state->registers.a = 8;
	state->registers.b = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->product[0] = 0;
	for (index = 0; index < 4; index++)
		state->buffer[index] = 0;
	for (;;) {
		port_u8 value = state->multiplier;
		port_u8 old_b;

		state->registers.a = (port_u8)(value >> 1);
		state->registers.f = 0;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		if (value & 1)
			state->registers.f |= PORT_FLAG_C;
		state->multiplier = state->registers.a;
		if (value & 1) {
			for (index = 4; index != 0; index--) {
				state->registers.a = state->buffer[index - 1];
				state->registers.c = state->registers.a;
				state->registers.a = state->product[index - 1];
				math_multiply_add(&state->registers,
					state->registers.c, index != 4);
				state->buffer[index - 1] = state->registers.a;
			}
		}
		old_b = state->registers.b;
		state->registers.b--;
		state->registers.f &= PORT_FLAG_C;
		state->registers.f |= PORT_FLAG_N;
		if (state->registers.b == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((old_b & 0x0f) == 0)
			state->registers.f |= PORT_FLAG_H;
		if (state->registers.b == 0)
			break;
		for (index = 4; index != 0; index--) {
			state->registers.a = state->product[index - 1];
			math_multiply_shift_left(&state->registers, index != 4);
			state->product[index - 1] = state->registers.a;
		}
	}
	for (index = 4; index != 0; index--) {
		state->registers.a = state->buffer[index - 1];
		state->product[index - 1] = state->registers.a;
	}
}

/*
 * Port of Multiply in home/math.asm:
 *   push hl / push bc / callfar _Multiply / pop bc / pop hl / ret.
 * callfar expands to ld hl,$7d41 / ld b,bank(_Multiply) / call Bankswitch,
 * and Bankswitch restores A to the pre-call hLoadedROMBank on return while
 * leaving F as _Multiply left it. BC and HL pass through unchanged and DE is
 * never touched. The rROMB mapper writes are hardware no-ops whose net effect
 * is the hLoadedROMBank save/restore modeled here.
 */
__attribute__((noinline, used)) void
port_math_multiply(struct math_multiply_state *state)
{
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;
	port_u8 saved_b = state->registers.b;
	port_u8 saved_c = state->registers.c;
	port_u8 old_bank = state->loaded_rom_bank;

	/* callfar: switch to bank BANK(_Multiply) = $0d and execute it. */
	state->loaded_rom_bank = 0x0d;
	math_multiply_body(state);
	/* Bankswitch epilogue: a = saved bank, banks restored. */
	state->registers.a = old_bank;
	state->loaded_rom_bank = old_bank;
	/* pop bc / pop hl / ret. */
	state->registers.b = saved_b;
	state->registers.c = saved_c;
	state->registers.h = saved_h;
	state->registers.l = saved_l;
}
