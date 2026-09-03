#include "port_state.h"

#define W_NPC_MOVEMENT_DIRECTIONS2_INDEX 0xcd37u
#define W_SCRIPTED_NPC_WALK_COUNTER 0xcf18u

void port_anim_scripted_npc_movement(struct cpu_register_state *, port_u8 *);

/* Port of InitScriptedNPCMovement in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_init_scripted_npc_movement(struct cpu_register_state *r, port_u8 *memory)
{
	r->a = 0;
	r->f = PORT_FLAG_Z;
	memory[W_NPC_MOVEMENT_DIRECTIONS2_INDEX] = r->a;
	r->a = 8;
	memory[W_SCRIPTED_NPC_WALK_COUNTER] = r->a;
	port_anim_scripted_npc_movement(r, memory);
}
