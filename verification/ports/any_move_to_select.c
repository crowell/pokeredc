#include "port_state.h"

struct any_move_to_select_state {
	struct cpu_register_state registers;
	port_u8 vblank_occurred;
};

#define AMTS_W_PLAYER_SELECTED_MOVE 0xccdcu
#define AMTS_W_BATTLE_MON_PP 0xd02du
#define AMTS_W_PLAYER_DISABLED_MOVE 0xd06du
#define AMTS_NO_MOVES_LEFT_TEXT 0x5430u
#define AMTS_STRUGGLE 0xa5u
#define AMTS_PP_MASK 0x3fu

void port_print_text(struct cpu_register_state *state, port_u8 *memory);
void port_delay_frames(struct delay_frame_state *state,
	const port_u8 *observations);

/* Port of AnyMoveToSelect in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_any_move_to_select(struct any_move_to_select_state *state, port_u8 *memory)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct cpu_register_state *registers = &state->registers;
	port_u16 hl;

	registers->a = AMTS_STRUGGLE;
	memory[AMTS_W_PLAYER_SELECTED_MOVE] = registers->a;
	registers->a = memory[AMTS_W_PLAYER_DISABLED_MOVE];
	state->registers.f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	registers->h = (port_u8)(AMTS_W_BATTLE_MON_PP >> 8);
	registers->l = (port_u8)AMTS_W_BATTLE_MON_PP;
	if (registers->a == 0) {
		hl = AMTS_W_BATTLE_MON_PP;
		registers->a = memory[hl++];
		registers->a |= memory[hl];
		hl++;
		registers->a |= memory[hl];
		hl++;
		registers->a |= memory[hl];
		registers->a &= AMTS_PP_MASK;
		registers->h = (port_u8)(hl >> 8);
		registers->l = (port_u8)hl;
		registers->f = PORT_FLAG_H;
		if (registers->a == 0)
			registers->f |= PORT_FLAG_Z;
		if (registers->a != 0)
			return;
	} else {
		registers->a = (port_u8)((registers->a << 4) |
			(registers->a >> 4));
		registers->a &= 0x0f;
		registers->f = PORT_FLAG_H;
		if (registers->a == 0)
			registers->f |= PORT_FLAG_Z;
		registers->b = registers->a;
		registers->d = 5;
		registers->a = 0;
		registers->f = PORT_FLAG_Z;
		hl = AMTS_W_BATTLE_MON_PP;
		for (;;) {
			registers->d--;
			if (registers->d == 0)
				break;
			registers->c = memory[hl++];
			registers->b--;
			if (registers->b == 0)
				continue;
			registers->a |= registers->c;
		}
		registers->h = (port_u8)(hl >> 8);
		registers->l = (port_u8)hl;
		registers->f = PORT_FLAG_H;
		if (registers->a == 0)
			registers->f |= PORT_FLAG_Z;
		if (registers->a != 0)
			return;
	}

	registers->h = (port_u8)(AMTS_NO_MOVES_LEFT_TEXT >> 8);
	registers->l = (port_u8)AMTS_NO_MOVES_LEFT_TEXT;
	port_print_text(registers, memory);
	registers->c = 60;
	{
		struct delay_frame_state delay;

		delay.registers = *registers;
		delay.vblank_occurred = state->vblank_occurred;
		delay.observed_vblank = 0;
		port_delay_frames(&delay, acknowledged_vblank);
		*registers = delay.registers;
		state->vblank_occurred = delay.vblank_occurred;
	}
	registers->a = 0;
	registers->f = PORT_FLAG_Z;
}
