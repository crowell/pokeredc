#include "port_state.h"

struct is_ghost_battle_state {
	struct cpu_register_state registers;
	port_u8 is_in_battle;
};

struct print_ghost_text_state {
	struct cpu_register_state registers;
	port_u8 is_in_battle;
	port_u8 whose_turn;
	port_u8 battle_mon_status;
};

extern void port_is_ghost_battle(struct is_ghost_battle_state *state);
extern void port_print_text(struct cpu_register_state *state, port_u8 *memory);

/* PrintGhostText, including IsGhostBattle and the text-dispatch calls. */
__attribute__((noinline, used)) void
port_print_ghost_text(struct print_ghost_text_state *state, port_u8 *memory)
{
	struct is_ghost_battle_state ghost = {
		state->registers,
		state->is_in_battle,
	};
	port_is_ghost_battle(&ghost);
	state->registers = ghost.registers;
	if ((state->registers.f & PORT_FLAG_Z) != 0) {
		state->registers.a = state->whose_turn;
		state->registers.f = PORT_FLAG_H;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		if (state->registers.a != 0) {
			state->registers.h = 0x58;
			state->registers.l = 0x35;
			port_print_text(&state->registers, memory);
			state->registers.a = 0;
			state->registers.f = PORT_FLAG_Z;
		} else {
			port_u8 frozen_or_sleeping =
				(port_u8)(state->battle_mon_status & 0x47);

			state->registers.a = frozen_or_sleeping;
			state->registers.f = PORT_FLAG_H;
			if (frozen_or_sleeping == 0)
				state->registers.f |= PORT_FLAG_Z;
			if (frozen_or_sleeping != 0)
				return;
			state->registers.h = 0x58;
			state->registers.l = 0x30;
			port_print_text(&state->registers, memory);
			state->registers.a = 0;
			state->registers.f = PORT_FLAG_Z;
		}
	}
}
