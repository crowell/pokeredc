#include "port_state.h"

void port_cable_club_draw_horizontal_line(
	struct cpu_register_state *, port_u8 *);

static port_u16
border_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
border_set_hl(struct cpu_register_state *registers, port_u16 value)
{
	registers->h = (port_u8)(value >> 8);
	registers->l = (port_u8)value;
}

static void
border_inc_a(struct cpu_register_state *registers)
{
	port_u8 old = registers->a;
	port_u8 carry = registers->f & PORT_FLAG_C;

	registers->a++;
	registers->f = carry;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0x0f)
		registers->f |= PORT_FLAG_H;
}

static void
border_add_hl_de(struct cpu_register_state *registers)
{
	port_u16 left = border_pair(registers->h, registers->l);
	port_u16 right = border_pair(registers->d, registers->e);
	unsigned long wide = (unsigned long)left + right;
	port_u8 flags = registers->f & PORT_FLAG_Z;

	if ((left & 0x0fff) + (right & 0x0fff) > 0x0fff)
		flags |= PORT_FLAG_H;
	if (wide > 0xffff)
		flags |= PORT_FLAG_C;
	registers->f = flags;
	border_set_hl(registers, (port_u16)wide);
}

static void
border_dec_b(struct cpu_register_state *registers)
{
	port_u8 old = registers->b;
	port_u8 carry = registers->f & PORT_FLAG_C;

	registers->b--;
	registers->f = (port_u8)(carry | PORT_FLAG_N);
	if (registers->b == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
border_write(struct cable_club_text_box_border_state *state,
	port_u8 *memory, port_u8 slot, port_u8 value, port_u8 increment)
{
	port_u16 address = border_pair(state->registers.h, state->registers.l);

	memory[address] = value;
	if (slot == 0) {
		state->written0 = value;
		state->write0_h = state->registers.h;
		state->write0_l = state->registers.l;
	} else {
		state->written1 = value;
		state->write1_h = state->registers.h;
		state->write1_l = state->registers.l;
	}
	if (increment != 0)
		border_set_hl(&state->registers, (port_u16)(address + 1));
}

__attribute__((noinline, used)) void
port_cable_club_text_box_border_top(
	struct cable_club_text_box_border_state *state, port_u8 *memory)
{
	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;
	state->registers.a = 0x78;
	border_write(state, memory, 0, state->registers.a, 1);
	border_inc_a(&state->registers);
	port_cable_club_draw_horizontal_line(&state->registers, memory);
	border_inc_a(&state->registers);
	border_write(state, memory, 1, state->registers.a, 0);
	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
	state->registers.d = 0;
	state->registers.e = 20;
	border_add_hl_de(&state->registers);
}

/* Returns one while another vertical border row remains. */
__attribute__((noinline, used)) port_u8
port_cable_club_text_box_border_row(
	struct cable_club_text_box_border_state *state, port_u8 *memory)
{
	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;
	state->registers.a = 0x7b;
	border_write(state, memory, 0, state->registers.a, 1);
	state->registers.a = 0x7f;
	port_cable_club_draw_horizontal_line(&state->registers, memory);
	border_write(state, memory, 1, 0x77, 0);
	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
	state->registers.d = 0;
	state->registers.e = 20;
	border_add_hl_de(&state->registers);
	border_dec_b(&state->registers);
	return state->registers.b != 0;
}

__attribute__((noinline, used)) void
port_cable_club_text_box_border_bottom(
	struct cable_club_text_box_border_state *state, port_u8 *memory)
{
	state->registers.a = 0x7c;
	border_write(state, memory, 0, state->registers.a, 1);
	state->registers.a = 0x76;
	port_cable_club_draw_horizontal_line(&state->registers, memory);
	border_write(state, memory, 1, 0x7d, 0);
}

/* Port of CableClub_TextBoxBorder in engine/link/cable_club.asm. */
__attribute__((noinline, used)) void
port_cable_club_text_box_border(
	struct cable_club_text_box_border_state *state, port_u8 *memory)
{
	port_cable_club_text_box_border_top(state, memory);
	do {
		(void)port_cable_club_text_box_border_row(state, memory);
	} while (state->registers.b != 0);
	port_cable_club_text_box_border_bottom(state, memory);
}
