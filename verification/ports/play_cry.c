#include "port_state.h"

#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u

void port_get_cry_data(struct cpu_register_state *, port_u8 *);
void port_play_sound(struct play_sound_state *);
void port_wait_for_sound_to_finish(struct wait_for_sound_state *);

/* Port of PlayCry in home/pokemon.asm. */
__attribute__((noinline, used)) void
port_play_cry(struct play_sound_state *state, port_u8 *memory)
{
	struct wait_for_sound_state wait;

	port_get_cry_data(&state->registers, memory);
	state->loaded_rom_bank = memory[H_LOADED_ROM_BANK];
	state->rom_bank = memory[R_ROMB];
	port_play_sound(state);
	memory[H_LOADED_ROM_BANK] = state->loaded_rom_bank;
	memory[R_ROMB] = state->rom_bank;

	wait.registers = state->registers;
	wait.low_health_alarm = state->low_health_alarm;
	wait.channel_sound_ids[0] = state->channel_sound_ids[0];
	wait.channel_sound_ids[1] = state->channel_sound_ids[1];
	wait.channel_sound_ids[2] = state->channel_sound_ids[3];
	port_wait_for_sound_to_finish(&wait);
	state->registers = wait.registers;
	state->channel_sound_ids[0] = wait.channel_sound_ids[0];
	state->channel_sound_ids[1] = wait.channel_sound_ids[1];
	state->channel_sound_ids[3] = wait.channel_sound_ids[2];
}
