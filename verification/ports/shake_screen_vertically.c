#include "port_state.h"

void port_play_applying_attack_sound(
	struct play_applying_attack_sound_state *);
void port_animation_shake_screen_vertically(
	struct animation_shake_vertical_state *);

/* Port of ShakeScreenVertically in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_shake_screen_vertically(struct shake_screen_vertically_state *state)
{
	struct animation_shake_vertical_state shake;
	port_u8 index;

	port_play_applying_attack_sound(&state->sound);
	shake.shake.registers = state->sound.sound.registers;
	shake.shake.registers.b = 8;
	for (index = 0; index < 6; index++)
		shake.shake.predef[index] = state->predef[index];
	shake.shake.disable_vblank_wy_update = state->disable_vblank_wy_update;
	shake.shake.mutate_wy = state->mutate_wy;
	shake.shake.wy = state->wy;
	shake.predef_id = state->predef_id;
	shake.predef_parent_bank = state->predef_parent_bank;
	shake.predef_bank = state->predef_bank;
	shake.loaded_rom_bank = state->sound.sound.loaded_rom_bank;
	shake.rom_bank = state->sound.sound.rom_bank;
	port_animation_shake_screen_vertically(&shake);

	state->sound.sound.registers = shake.shake.registers;
	for (index = 0; index < 6; index++)
		state->predef[index] = shake.shake.predef[index];
	state->disable_vblank_wy_update = shake.shake.disable_vblank_wy_update;
	state->mutate_wy = shake.shake.mutate_wy;
	state->wy = shake.shake.wy;
	state->predef_id = shake.predef_id;
	state->predef_parent_bank = shake.predef_parent_bank;
	state->predef_bank = shake.predef_bank;
	state->sound.sound.loaded_rom_bank = shake.loaded_rom_bank;
	state->sound.sound.rom_bank = shake.rom_bank;
}
