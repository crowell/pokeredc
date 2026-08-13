#include "port_state.h"

static port_u16
ailment_address(port_u16 de, port_u16 hl, port_u8 index)
{
	if (index == 0)
		return de;
	return (port_u16)(hl + index - 1);
}

static void
ailment_store(struct status_ailment_text_state *state, port_u16 de,
	port_u16 initial_hl, port_u16 address, port_u8 value)
{
	port_u8 index;

	for (index = 0; index < 4; index++)
		if (ailment_address(de, initial_hl, index) == address)
			state->memory[index] = value;
}

static void
ailment_bit(struct cpu_register_state *registers, port_u8 bit)
{
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_H;
	if ((registers->a & (1 << bit)) == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
ailment_write(struct status_ailment_text_state *state, port_u16 de,
	port_u16 initial_hl, port_u8 first, port_u8 second, port_u8 third)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);

	state->registers.a = first;
	ailment_store(state, de, initial_hl, hl, state->registers.a);
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = second;
	ailment_store(state, de, initial_hl, hl, state->registers.a);
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	ailment_store(state, de, initial_hl, hl, third);
}

/* Port of PrintStatusAilment in engine/pokemon/status_ailments.asm. */
__attribute__((noinline, used)) void
port_print_status_ailment(struct status_ailment_text_state *state)
{
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 status = state->memory[0];

	state->registers.a = status;
	ailment_bit(&state->registers, 3);
	if ((status & 0x08) != 0) {
		ailment_write(state, de, hl, 0x8f, 0x92, 0x8d);
		return;
	}
	ailment_bit(&state->registers, 4);
	if ((status & 0x10) != 0) {
		ailment_write(state, de, hl, 0x81, 0x91, 0x8d);
		return;
	}
	ailment_bit(&state->registers, 5);
	if ((status & 0x20) != 0) {
		ailment_write(state, de, hl, 0x85, 0x91, 0x99);
		return;
	}
	ailment_bit(&state->registers, 6);
	if ((status & 0x40) != 0) {
		ailment_write(state, de, hl, 0x8f, 0x80, 0x91);
		return;
	}
	state->registers.a &= 7;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		return;
	}
	ailment_write(state, de, hl, 0x92, 0x8b, 0x8f);
}
