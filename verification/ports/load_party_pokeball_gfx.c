#include "port_state.h"

void port_copy_video_data(struct cpu_register_state *, port_u8 *);

static void
load_party_pokeball_gfx_setup(struct cpu_register_state *registers)
{
	registers->d = 0x69;
	registers->e = 0x7e;
	registers->h = 0x83;
	registers->l = 0x10;
	registers->b = 0x0e;
	registers->c = 4;
}

/* Compatibility setup used by older partial callers. */
__attribute__((noinline, used)) void
port_load_party_pokeball_gfx(struct cpu_register_state *registers)
{
	load_party_pokeball_gfx_setup(registers);
}

/* Port of LoadPartyPokeballGfx in draw_hud_pokeball_gfx.asm. */
__attribute__((noinline, used)) void
port_load_party_pokeball_gfx_with_memory(
	struct cpu_register_state *registers, port_u8 *memory)
{
	load_party_pokeball_gfx_setup(registers);
	port_copy_video_data(registers, memory);
}
