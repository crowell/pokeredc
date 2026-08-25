#include "port_state.h"

struct read_player_mon_cur_hp_state {
	struct cpu_register_state registers;
};

#define RPM_W_PLAYER_MON_NUMBER 0xcc2fu
#define RPM_W_PARTY_MON_1_HP 0xd16cu
#define RPM_W_BATTLE_MON_HP 0xd015u
#define RPM_PARTY_MON_STRUCT_LENGTH 0x2cu
#define RPM_COPY_LENGTH 4u

void port_add_n_times(struct cpu_register_state *state);
void port_copy_data(struct cpu_register_state *state, port_u8 *memory);

/* Port of ReadPlayerMonCurHPAndStatus in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_read_player_mon_cur_hp_status(struct read_player_mon_cur_hp_state *state,
	port_u8 *memory)
{
	state->registers.a = memory[RPM_W_PLAYER_MON_NUMBER];
	state->registers.b = 0;
	state->registers.c = RPM_PARTY_MON_STRUCT_LENGTH;
	state->registers.h = (port_u8)(RPM_W_PARTY_MON_1_HP >> 8);
	state->registers.l = (port_u8)RPM_W_PARTY_MON_1_HP;
	port_add_n_times(&state->registers);
	state->registers.d = state->registers.h;
	state->registers.e = state->registers.l;
	state->registers.h = (port_u8)(RPM_W_BATTLE_MON_HP >> 8);
	state->registers.l = (port_u8)RPM_W_BATTLE_MON_HP;
	state->registers.b = 0;
	state->registers.c = RPM_COPY_LENGTH;
	port_copy_data(&state->registers, memory);
}
