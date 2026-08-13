#include "port_state.h"

__attribute__((noinline, used)) void
port_bankswitch_begin(struct bankswitch_state *state)
{
	state->registers.a = state->loaded_rom_bank;
	state->saved_a = state->registers.a;
	state->saved_f = state->registers.f;
	state->registers.a = state->registers.b;
	state->loaded_rom_bank = state->registers.a;
	state->mapper_bank = state->registers.a;
	state->registers.b = 0x35;
	state->registers.c = 0xe4;
}

__attribute__((noinline, used)) void
port_bankswitch_return(struct bankswitch_state *state)
{
	state->registers.b = state->saved_a;
	state->registers.c = state->saved_f;
	state->registers.a = state->registers.b;
	state->loaded_rom_bank = state->registers.a;
	state->mapper_bank = state->registers.a;
}

/* Port of Bankswitch in home/bankswitch.asm. */
__attribute__((noinline, used)) void
port_bankswitch(struct bankswitch_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_banks[2])
{
	port_bankswitch_begin(state);
	/* JP HL is an explicit arbitrary callback boundary. */
	state->registers = *callback_registers;
	state->loaded_rom_bank = callback_banks[0];
	state->mapper_bank = callback_banks[1];
	port_bankswitch_return(state);
}
