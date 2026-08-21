#include "port_state.h"

/* Port of MarowakAnim through CopyMonPicFromBGToSpriteVRAM. */
__attribute__((noinline, used)) void
port_marowak_anim(struct cpu_register_state *registers)
{
	registers->a = 0xe4;
}
