#include "port_state.h"

struct run_selected_state {
	struct cpu_register_state registers;
	port_u8 current_menu_item;
};

/* Port of BattleMenu_RunWasSelected through TryRunningFromBattle. */
__attribute__((noinline, used)) void
port_battle_menu_run_was_selected(struct run_selected_state *state)
{
	state->registers.a = 3;
	state->current_menu_item = 3;
	state->registers.h = 0xd0;
	state->registers.l = 0x29;
	state->registers.d = 0xcf;
	state->registers.e = 0xfa;
}
