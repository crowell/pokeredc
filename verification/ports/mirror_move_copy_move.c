#include "port_state.h"

#define MM_H_WHOSE_TURN 0xfff3u
#define MM_W_PLAYER_SELECTED_MOVE 0xccdcu
#define MM_W_ENEMY_SELECTED_MOVE 0xccddu
#define MM_W_PLAYER_USED_MOVE 0xccf1u
#define MM_W_ENEMY_USED_MOVE 0xccf2u
#define MM_W_PLAYER_MOVE_NUM 0xcfd2u
#define MM_W_ENEMY_MOVE_NUM 0xcfccu
#define MM_FAILED_TEXT 0x6324u
#define MM_MIRROR_MOVE 0x77u

void port_print_text(struct cpu_register_state *state, port_u8 *memory);
void port_reload_move_data(struct reload_move_data_state *state,
	port_u8 *memory);

static void
set_and_a_flags(struct cpu_register_state *registers)
{
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
set_cp_flags(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	port_u8 result = (port_u8)(left - right);
	registers->f = PORT_FLAG_N;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

/* Port of MirrorMoveCopyMove in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_mirror_move_copy_move(struct reload_move_data_state *state,
	port_u8 *memory)
{
	struct cpu_register_state *registers = &state->registers;
	port_u8 whose = memory[MM_H_WHOSE_TURN];
	port_u16 selected;

	registers->a = whose;
	set_and_a_flags(registers);
	if (whose == 0) {
		registers->a = memory[MM_W_ENEMY_USED_MOVE];
		registers->h = (port_u8)(MM_W_PLAYER_SELECTED_MOVE >> 8);
		registers->l = (port_u8)MM_W_PLAYER_SELECTED_MOVE;
		registers->d = (port_u8)(MM_W_PLAYER_MOVE_NUM >> 8);
		registers->e = (port_u8)MM_W_PLAYER_MOVE_NUM;
		selected = MM_W_PLAYER_SELECTED_MOVE;
	} else {
		registers->a = memory[MM_W_PLAYER_USED_MOVE];
		registers->d = (port_u8)(MM_W_ENEMY_MOVE_NUM >> 8);
		registers->e = (port_u8)MM_W_ENEMY_MOVE_NUM;
		registers->h = (port_u8)(MM_W_ENEMY_SELECTED_MOVE >> 8);
		registers->l = (port_u8)MM_W_ENEMY_SELECTED_MOVE;
		selected = MM_W_ENEMY_SELECTED_MOVE;
	}
	memory[selected] = registers->a;
	set_cp_flags(registers, MM_MIRROR_MOVE);
	if (!(registers->f & PORT_FLAG_Z)) {
		set_and_a_flags(registers);
		if (!(registers->f & PORT_FLAG_Z)) {
			port_reload_move_data(state, memory);
			return;
		}
	}
	registers->h = (port_u8)(MM_FAILED_TEXT >> 8);
	registers->l = (port_u8)MM_FAILED_TEXT;
	port_print_text(registers, memory);
	registers->a = 0;
	registers->f = PORT_FLAG_Z;
}
