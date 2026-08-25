#include "port_state.h"

struct is_ghost_battle_state {
	struct cpu_register_state registers;
	port_u8 is_in_battle;
};

struct is_ghost_battle_complete_state {
	struct cpu_register_state registers;
};

#define IGB_W_IS_IN_BATTLE 0xd057u
#define IGB_W_CUR_MAP 0xd35eu
#define IGB_POKEMON_TOWER_1F 0x8eu
#define IGB_POKEMON_TOWER_7F_PLUS_1 0x95u
#define IGB_SILPH_SCOPE 0x48u

void port_is_item_in_bag(struct cpu_register_state *state, port_u8 *memory);

static void
dec_a(struct cpu_register_state *registers)
{
	port_u8 old = registers->a;

	registers->a--;
	registers->f = (port_u8)((registers->f & PORT_FLAG_C) | PORT_FLAG_N);
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
cp_a(struct cpu_register_state *registers, port_u8 value)
{
	port_u8 a = registers->a;
	port_u8 result = (port_u8)(a - value);

	registers->f = PORT_FLAG_N;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((a & 0x0f) < (value & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (a < value)
		registers->f |= PORT_FLAG_C;
}

/* Compatibility entry used by the existing PrintGhostText port. */
__attribute__((noinline, used)) void
port_is_ghost_battle(struct is_ghost_battle_state *state)
{
	state->registers.a = state->is_in_battle;
	dec_a(&state->registers);
}

/* Complete port of IsGhostBattle in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_is_ghost_battle_complete(struct is_ghost_battle_complete_state *state,
	port_u8 *memory)
{
	struct cpu_register_state *registers = &state->registers;

	registers->a = memory[IGB_W_IS_IN_BATTLE];
	dec_a(registers);
	if (registers->a != 0)
		return;
	registers->a = memory[IGB_W_CUR_MAP];
	cp_a(registers, IGB_POKEMON_TOWER_1F);
	if (registers->f & PORT_FLAG_C)
		goto not_ghost;
	cp_a(registers, IGB_POKEMON_TOWER_7F_PLUS_1);
	if (!(registers->f & PORT_FLAG_C))
		goto not_ghost;
	registers->b = IGB_SILPH_SCOPE;
	port_is_item_in_bag(registers, memory);
	if (registers->f & PORT_FLAG_Z)
		return;

not_ghost:
	registers->a = 1;
	registers->f = PORT_FLAG_H;
}
