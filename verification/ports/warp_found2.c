#include "port_state.h"

#define W_NUMBER_OF_WARPS 0xd3aeu
#define W_WARPED_FROM_WHICH_WARP 0xd73bu
#define W_CUR_MAP 0xd35eu
#define W_WARPED_FROM_WHICH_MAP 0xd73cu

void port_check_if_in_outside_map(struct memory_predicate_state *);

/* Port of WarpFound2 through the CheckIfInOutsideMap call boundary. */
__attribute__((noinline, used)) void
port_warp_found2(struct cpu_register_state *state, port_u8 *memory)
{
	struct memory_predicate_state predicate = {0};

	state->a = (port_u8)(memory[W_NUMBER_OF_WARPS] - state->c);
	memory[W_WARPED_FROM_WHICH_WARP] = state->a;
	state->a = memory[W_CUR_MAP];
	memory[W_WARPED_FROM_WHICH_MAP] = state->a;
	predicate.registers = *state;
	predicate.value = state->a;
	port_check_if_in_outside_map(&predicate);
	*state = predicate.registers;
}
