#include "port_state.h"

/* RedsHouse2FDefaultScript, scripts/RedsHouse2F.asm. This is the entire
 * leaf, not a call-boundary marker. test_reds_house2_f_default_script.py
 * executes all 14 linked bytes with only the three SM83 store instructions
 * shimmed and compares registers, canonical flags and all three WRAM/HRAM
 * outputs. This proof does not extend to the calling runtime dispatcher. */
__attribute__((noinline, used)) void
port_reds_house2_f_default_script(struct cpu_register_state *r, port_u8 *m)
{
	r->a = 0;
	r->f = PORT_FLAG_Z;
	m[0xffb4] = 0; /* hJoyHeld */
	r->a = 8; /* PLAYER_DIR_UP */
	m[0xd528] = r->a;
	r->a = 1; /* SCRIPT_REDSHOUSE2F_NOOP */
	m[0xd60c] = r->a;
}
