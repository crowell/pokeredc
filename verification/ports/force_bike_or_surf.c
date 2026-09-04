#include "port_state.h"

#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u
#define W_STATUS_FLAGS4 0xd72eu
#define W_LOW_HEALTH_ALARM 0xd083u
#define W_CHANNEL_SOUND_IDS 0xc026u
#define W_LAST_MUSIC_SOUND_ID 0xcfcau
#define RED_SPRITE_BANK 5u /* BANK(RedSprite) */
#define LOAD_PLAYER_SPRITE_GRAPHICS 0x0997u

void port_bankswitch_begin(struct bankswitch_state *);
void port_bankswitch_return(struct bankswitch_state *);
void port_load_player_sprite_graphics(struct cpu_register_state *, port_u8 *);
void port_play_default_music(struct default_music_fade_state *,
	const struct cpu_register_state *, const port_u8[2]);

/* Port of ForceBikeOrSurf in home/overworld.asm.
 *
 * The assembly calls Bankswitch to enter LoadPlayerSpriteGraphics, whose
 * return restores the caller bank/AF through BC, then tail-jumps into the
 * proven PlayDefaultMusic continuation. */
__attribute__((noinline, used)) void
port_force_bike_or_surf(struct force_bike_or_surf_state *state,
	port_u8 *memory)
{
	struct bankswitch_state bank = {0};
	struct default_music_fade_state music = {0};
	port_u8 callback_globals[2];

	bank.registers = state->registers;
	bank.loaded_rom_bank = memory[H_LOADED_ROM_BANK];
	bank.mapper_bank = memory[R_ROMB];
	bank.registers.b = RED_SPRITE_BANK;
	bank.registers.h = (port_u8)(LOAD_PLAYER_SPRITE_GRAPHICS >> 8);
	bank.registers.l = (port_u8)LOAD_PLAYER_SPRITE_GRAPHICS;
	port_bankswitch_begin(&bank);
	memory[H_LOADED_ROM_BANK] = bank.loaded_rom_bank;
	memory[R_ROMB] = bank.mapper_bank;

	/* Bankswitch's JP HL enters the real bank-0 graphics loader. */
	port_load_player_sprite_graphics(&bank.registers, memory);
	bank.loaded_rom_bank = memory[H_LOADED_ROM_BANK];
	bank.mapper_bank = memory[R_ROMB];
	port_bankswitch_return(&bank);
	state->registers = bank.registers;
	memory[H_LOADED_ROM_BANK] = bank.loaded_rom_bank;
	memory[R_ROMB] = bank.mapper_bank;

	music.registers = state->registers;
	music.status_flags4 = memory[W_STATUS_FLAGS4];
	music.last_music_sound_id = memory[W_LAST_MUSIC_SOUND_ID];
	music.low_health_alarm = memory[W_LOW_HEALTH_ALARM];
	for (port_u8 i = 0; i < 3u; ++i)
		music.channel_sound_ids[i] = memory[W_CHANNEL_SOUND_IDS + i];
	callback_globals[0] = state->music_callback_status_flags4;
	callback_globals[1] = state->music_callback_last_music_sound_id;
	port_play_default_music(&music, &state->music_callback_registers,
		callback_globals);
	state->registers = music.registers;
	memory[W_STATUS_FLAGS4] = music.status_flags4;
	memory[W_LAST_MUSIC_SOUND_ID] = music.last_music_sound_id;
	memory[W_LOW_HEALTH_ALARM] = music.low_health_alarm;
	for (port_u8 i = 0; i < 3u; ++i)
		memory[W_CHANNEL_SOUND_IDS + i] = music.channel_sound_ids[i];
}
