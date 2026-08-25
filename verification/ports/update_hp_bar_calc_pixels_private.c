#include "port_state.h"

struct update_hp_bar_calc_pixels_private_state {
	struct cpu_register_state registers;
	port_u8 max_low;
	port_u8 max_high;
	port_u8 old_low;
	port_u8 old_high;
	port_u8 new_low;
	port_u8 new_high;
	port_u8 math[4];
	port_u8 divisor;
	port_u8 buffer[5];
	port_u8 loaded_rom_bank;
	port_u8 mapper_bank;
};

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

static void
calc_hp_pixels(struct update_hp_bar_calc_pixels_private_state *state)
{
	struct get_hp_bar_length_private_state hp;
	port_u8 index;

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

/* Port of the complete UpdateHPBar_CalcOldNewHPBarPixels function. */
__attribute__((noinline, used)) void
port_update_hp_bar_calc_pixels_private(
	struct update_hp_bar_calc_pixels_private_state *state)
{
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;
	port_u8 old_pixels;
	port_u8 old_flags;

	state->registers.e = state->max_low;
	state->registers.d = state->max_high;
	state->registers.c = state->old_low;
	state->registers.b = state->old_high;
	state->registers.l = state->new_low;
	state->registers.h = state->new_high;
	state->registers.a = state->new_low;
	calc_hp_pixels(state);
	old_pixels = state->registers.e;
	old_flags = state->registers.f;
	state->registers.a = old_pixels;
	state->registers.e = state->max_low;
	state->registers.d = state->max_high;
	state->registers.c = state->new_low;
	state->registers.b = state->new_high;
	calc_hp_pixels(state);
	state->registers.a = old_pixels;
	state->registers.f = old_flags;
	state->registers.d = state->registers.e;
	state->registers.e = state->registers.a;
	state->registers.h = saved_h;
	state->registers.l = saved_l;
}
