#include "port_state.h"

/* Port of ReadMove in engine/battle/trainer_ai.asm.
 *
 * Given a 1-based move id in A, copies that move's MOVE_LENGTH-byte data block
 * from the ROM Moves table into wEnemyMoveNum. */

#define RM_MOVES_ADDR 0x4000u
#define RM_MOVE_LENGTH 6u
#define RM_W_ENEMY_MOVE_NUM 0xcfccu

__attribute__((noinline, used)) void
port_read_move(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 a = (port_u8)(state->a - 1);
	port_u16 hl = (port_u16)(RM_MOVES_ADDR + RM_MOVE_LENGTH * a);
	port_u16 de = RM_W_ENEMY_MOVE_NUM;
	for (port_u16 i = 0; i < RM_MOVE_LENGTH; i++) {
		memory[de + i] = memory[hl + i];
	}
}
