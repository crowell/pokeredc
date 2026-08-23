#include "port_state.h"

void port_add_n_times(struct cpu_register_state *);
void port_get_selected_move_offset2(struct memory_predicate_state *);

/* Port of GetSelectedMoveOffset in engine/items/item_effects.asm. */
__attribute__((noinline, used)) void
port_get_selected_move_offset(struct selected_move_offset_state *state)
{
	struct memory_predicate_state selected;

	state->registers.a = state->which_pokemon;
	port_add_n_times(&state->registers);
	selected.registers = state->registers;
	selected.value = state->current_menu_item;
	port_get_selected_move_offset2(&selected);
	state->registers = selected.registers;
}
