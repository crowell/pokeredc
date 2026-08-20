#include "port_state.h"

/* Port of the setup prefix of AnimationFallingObjects in
 * engine/battle/animations.asm. InitMultipleObjectsOAM is the explicit
 * continuation boundary after loading the object count and tileset ID. */
__attribute__((noinline, used)) void
port_animation_falling_objects_setup(struct cpu_register_state *state)
{
	state->c = state->a;
	state->a = 1;
}
