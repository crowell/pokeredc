#include "port_state.h"
#ifdef PORT_PLATFORM_RUNTIME
port_u8 port_uncompress_sprite_data(struct cpu_register_state *, port_u8 *);
#endif

/*
 * UncompressSpriteFromDE: 21 abd0 73 23 72 c3 fd24
 *   LD HL, 0xd0ab
 *   LD (HL), E
 *   INC HL
 *   LD (HL), D
 *   JP 0x24fd
 *
 * Stores the sprite source pointer (DE) into the temp buffer at 0xd0ab
 * (low byte first), then hands off to the shared uncompress routine.
 * LD (HL),r and INC HL do not affect registers or flags, so only HL and
 * the two written bytes change.
 */
__attribute__((noinline, used))
void port_uncompress_sprite_from_de(struct cpu_register_state *state, port_u8 *memory)
{
	memory[0xd0ab] = state->e;
	memory[0xd0ac] = state->d;
	state->h = 0xd0;
	state->l = 0xac;
#ifdef PORT_PLATFORM_RUNTIME
	/* The legacy proof ends at JP UncompressSpriteData. Runtime must
	 * execute its continuation; its composed proof is still pending. */
	port_uncompress_sprite_data(state, memory);
#endif
}
