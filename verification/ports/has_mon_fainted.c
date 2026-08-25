#include "port_state.h"

struct has_mon_fainted_state {
	struct cpu_register_state registers;
};

#define HMF_W_WHICH_POKEMON 0xcf92u
#define HMF_W_FIRST_MONS_NOT_OUT_YET 0xd11du
#define HMF_W_PARTY_MON_1_HP 0xd16cu
#define HMF_PARTY_MON_STRUCT_LENGTH 0x2cu
#define HMF_NO_WILL_TEXT 0x4ab4u

void port_add_n_times(struct cpu_register_state *state);
void port_print_text(struct cpu_register_state *state, port_u8 *memory);

/* Port of HasMonFainted in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_has_mon_fainted(struct has_mon_fainted_state *state, port_u8 *memory)
{
	port_u16 hl;

	state->registers.a = memory[HMF_W_WHICH_POKEMON];
	state->registers.h = (port_u8)(HMF_W_PARTY_MON_1_HP >> 8);
	state->registers.l = (port_u8)HMF_W_PARTY_MON_1_HP;
	state->registers.b = 0;
	state->registers.c = HMF_PARTY_MON_STRUCT_LENGTH;
	port_add_n_times(&state->registers);
	hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	state->registers.a = memory[hl++];
	state->registers.a |= memory[hl];
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	if (state->registers.a != 0)
		return;
	state->registers.a = memory[HMF_W_FIRST_MONS_NOT_OUT_YET];
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a == 0) {
		state->registers.h = (port_u8)(HMF_NO_WILL_TEXT >> 8);
		state->registers.l = (port_u8)HMF_NO_WILL_TEXT;
		port_print_text(&state->registers, memory);
	}
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
}
