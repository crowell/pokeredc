#include "port_state.h"

struct hp_bar_length_private_state {
	struct cpu_register_state registers;
	port_u8 predef[6];
	port_u8 math[4];
	port_u8 divisor;
	port_u8 buffer[5];
	port_u8 loaded_rom_bank;
	port_u8 mapper_bank;
};

void port_get_predef_registers(struct register_memory_state *state);

struct get_hp_bar_length_private_state {
	struct cpu_register_state registers;
	port_u8 math[4];
	port_u8 divisor;
	port_u8 buffer[5];
	port_u8 loaded_rom_bank;
	port_u8 mapper_bank;
};

void port_get_hp_bar_length_private(
    struct get_hp_bar_length_private_state *state);

/* Port of the complete HPBarLength function. */
__attribute__((noinline, used)) void
port_hp_bar_length_private(struct hp_bar_length_private_state *state)
{
	struct register_memory_state predef;
	struct get_hp_bar_length_private_state hp;
	port_u8 index;

	predef.registers = state->registers;
	for (index = 0; index < 6; index++)
		predef.memory[index] = state->predef[index];
	port_get_predef_registers(&predef);
	state->registers = predef.registers;
	for (index = 0; index < 6; index++)
		state->predef[index] = predef.memory[index];

	hp.registers = state->registers;
	for (index = 0; index < 4; index++)
		hp.math[index] = state->math[index];
	hp.divisor = state->divisor;
	for (index = 0; index < 5; index++)
		hp.buffer[index] = state->buffer[index];
	hp.loaded_rom_bank = state->loaded_rom_bank;
	hp.mapper_bank = state->mapper_bank;
	port_get_hp_bar_length_private(&hp);
	state->registers = hp.registers;
	for (index = 0; index < 4; index++)
		state->math[index] = hp.math[index];
	state->divisor = hp.divisor;
	for (index = 0; index < 5; index++)
		state->buffer[index] = hp.buffer[index];
	state->loaded_rom_bank = hp.loaded_rom_bank;
	state->mapper_bank = hp.mapper_bank;
}
