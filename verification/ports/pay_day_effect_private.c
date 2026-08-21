#include "port_state.h"

struct pay_day_private_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 battle_level;
	port_u8 enemy_level;
};

/* Port of PayDayEffect_ through level doubling. */
__attribute__((noinline, used)) void
port_pay_day_effect_private(struct pay_day_private_state *state)
{
	port_u8 level = state->whose_turn == 0 ? state->battle_level : state->enemy_level;
	port_u16 wide = (port_u16)level + level;
	state->registers.h = 0xcd;
	state->registers.l = 0x6e;
	state->registers.a = (port_u8)wide;
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((level & 0x0f) + (level & 0x0f) > 0x0f)
		state->registers.f |= PORT_FLAG_H;
	if (wide > 0xff)
		state->registers.f |= PORT_FLAG_C;
}
