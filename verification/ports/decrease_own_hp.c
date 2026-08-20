#include "port_state.h"

/* Port of HandlePoisonBurnLeechSeed_DecreaseOwnHP through the max-HP
 * pointer calculation before its first memory load. */
__attribute__((noinline, used)) void
port_decrease_own_hp_setup(struct cpu_register_state *registers)
{
	port_u16 hl = (port_u16)(((port_u16)registers->h << 8) | registers->l);
	unsigned int wide;

	registers->b = 0;
	registers->c = 0x0e;
	wide = (unsigned int)hl + 0x0e;
	registers->h = (port_u8)(wide >> 8);
	registers->l = (port_u8)wide;
	registers->f &= PORT_FLAG_Z;
	if ((hl & 0x0fff) + 0x0e > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xffff)
		registers->f |= PORT_FLAG_C;
}
