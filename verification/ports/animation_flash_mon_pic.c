#include "port_state.h"

#define W_BATTLE_MON_SPECIES 0xd014
#define W_ENEMY_MON_SPECIES 0xcfe5
#define W_CHANGE_MON_PIC_ENEMY_TURN_SPECIES 0xcee9
#define W_CHANGE_MON_PIC_PLAYER_TURN_SPECIES 0xceea

/* ChangeMonPic is the explicit continuation boundary for this entry. */
__attribute__((noinline, used)) void
port_animation_flash_mon_pic(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 player = memory[W_BATTLE_MON_SPECIES];
	port_u8 enemy = memory[W_ENEMY_MON_SPECIES];
	memory[W_CHANGE_MON_PIC_PLAYER_TURN_SPECIES] = player;
	memory[W_CHANGE_MON_PIC_ENEMY_TURN_SPECIES] = enemy;
	state->a = enemy;
}
