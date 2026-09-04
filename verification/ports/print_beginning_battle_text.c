#include "port_state.h"

struct print_beginning_battle_text_state {
	struct cpu_register_state registers;
	port_u8 is_in_battle;
	port_u8 cur_map;
	port_u8 enemy_species;
	port_u8 move_missed;
};

#define POKEMON_TOWER_3F 0x90u
#define POKEMON_TOWER_7F_PLUS_ONE 0x95u
#define WILD_MON_APPEARED_TEXT 0x4e3bu
#define HOOKED_MON_ATTACKED_TEXT 0x4e40u
#define TRAINER_WANTS_TO_FIGHT_TEXT 0x4e4au

/* Port of PrintBeginningBattleText through wild/trainer selection and the
 * non-Tower text-pointer setup. Cry, sound, delay, Tower handling, Pokeball
 * drawing, and PrintText remain explicit callee boundaries. */
__attribute__((noinline, used)) void
port_print_beginning_battle_text(struct print_beginning_battle_text_state *state)
{
	port_u8 old = state->is_in_battle;
	port_u8 result = (port_u8)(old - 1);

	state->registers.a = result;
	state->registers.f = state->registers.f & PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (result == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	if (result != 0u) {
		state->registers.h = (port_u8)(TRAINER_WANTS_TO_FIGHT_TEXT >> 8);
		state->registers.l = (port_u8)TRAINER_WANTS_TO_FIGHT_TEXT;
		return;
	}
	if (state->cur_map >= POKEMON_TOWER_3F &&
	    state->cur_map < POKEMON_TOWER_7F_PLUS_ONE)
		return;
	state->registers.a = state->enemy_species;
	{
		port_u16 text = state->move_missed != 0u ?
			HOOKED_MON_ATTACKED_TEXT : WILD_MON_APPEARED_TEXT;
		state->registers.h = (port_u8)(text >> 8);
		state->registers.l = (port_u8)text;
	}
}
