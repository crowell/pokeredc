#include "port_state.h"

struct test_battle_private_state {
	struct cpu_register_state registers;
	port_u8 obtained_badges;
	port_u8 status_flags7;
};

/* Port of TestBattle through test-battle badge/status setup. */
__attribute__((noinline, used)) void
port_test_battle_private(struct test_battle_private_state *state)
{
	state->registers.a = 0x80;
	state->obtained_badges = 0x80;
	state->status_flags7 |= 0x40;
	state->registers.h = 0xd7;
	state->registers.l = 0x33;
}
