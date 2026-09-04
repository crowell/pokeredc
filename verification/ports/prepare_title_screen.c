#include "port_state.h"

/* Port of PrepareTitleScreen in engine/movie/title.asm. */

#define DEBUG_NEW_GAME_PLAYER_NAME 0x45aau
#define DEBUG_NEW_GAME_RIVAL_NAME 0x45b1u
#define NAME_LENGTH 11u
#define W_PLAYER_NAME 0xd158u
#define W_RIVAL_NAME 0xd34au
#define H_WY 0xffb0u
#define W_LETTER_PRINTING_DELAY_FLAGS 0xd358u
#define W_STATUS_FLAGS6 0xd732u
#define W_AUDIO_ROM_BANK 0xc0efu
#define W_AUDIO_SAVED_ROM_BANK 0xc0f0u
#define MUSIC_TITLE_SCREEN_BANK 0x1fu
#define PORT_FLAG_Z 0x80u

static void
copy_name(port_u8 *memory, port_u16 source, port_u16 destination)
{
	port_u8 i;

	for (i = 0; i < NAME_LENGTH; ++i)
		memory[destination + i] = memory[source + i];
}

__attribute__((noinline, used)) void
port_prepare_title_screen(struct cpu_register_state *state, port_u8 *memory)
{
	copy_name(memory, DEBUG_NEW_GAME_PLAYER_NAME, W_PLAYER_NAME);
	copy_name(memory, DEBUG_NEW_GAME_RIVAL_NAME, W_RIVAL_NAME);

	state->a = 0;
	state->f = PORT_FLAG_Z;
	memory[H_WY] = state->a;
	memory[W_LETTER_PRINTING_DELAY_FLAGS] = state->a;
	memory[W_STATUS_FLAGS6] = state->a;
	memory[W_STATUS_FLAGS6 + 1] = state->a;
	memory[W_STATUS_FLAGS6 + 2] = state->a;
	memory[W_AUDIO_ROM_BANK] = MUSIC_TITLE_SCREEN_BANK;
	memory[W_AUDIO_SAVED_ROM_BANK] = MUSIC_TITLE_SCREEN_BANK;
	state->h = (port_u8)(W_STATUS_FLAGS6 >> 8);
	state->d = (port_u8)((W_RIVAL_NAME + NAME_LENGTH) >> 8);
	state->e = (port_u8)((W_RIVAL_NAME + NAME_LENGTH) & 0xffu);
	state->l = (port_u8)((W_STATUS_FLAGS6 + 2) & 0xffu);
	state->a = MUSIC_TITLE_SCREEN_BANK;
}
