#include "port_state.h"

struct play_battle_victory_music_state {
	struct cpu_register_state registers;
	port_u8 new_sound_id;
};

/* Port of PlayBattleVictoryMusic through the PlayMusic call. */
__attribute__((noinline, used)) void
port_play_battle_victory_music(struct play_battle_victory_music_state *state)
{
	state->new_sound_id = 0xff;
	state->registers.c = 8;
}
