#include "port_state.h"

extern void port_delay3(struct cpu_register_state *state, port_u8 *memory);
static port_u8 animation_memory[0x10000];

/* Port of PlayMoveAnimation through the MoveAnimation predef boundary. */
__attribute__((noinline, used)) void
port_play_move_animation(struct cpu_register_state *registers)
{
	/* A is stored in wAnimationID by the assembly before Delay3. */
	port_delay3(registers, animation_memory);
}
