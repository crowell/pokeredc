#include "port_state.h"

#define W_ON_SGB 0xcf1bu
#define PALETTE_COMMAND_PREDEF 0x45u

struct run_palette_command_private_state {
	struct cpu_register_state registers;
};

void port_run_palette_command_private(
	struct run_palette_command_private_state *, port_u8 *);

/* Port of RunPaletteCommand in home/palettes.asm. */
__attribute__((noinline, used)) void
port_run_palette_command(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u8 on_sgb = memory[W_ON_SGB];

	registers->a = on_sgb;
	registers->f = PORT_FLAG_H;
	if (on_sgb == 0)
		registers->f |= PORT_FLAG_Z;
	if (on_sgb == 0)
		return;

	/* predef_jump loads the _RunPaletteCommand predef ID before entering
	 * the dispatcher.  The private port is the audited continuation for the
	 * palette-command body, so preserve that call convention here. */
	registers->a = PALETTE_COMMAND_PREDEF;
	{
		struct run_palette_command_private_state state;
		state.registers = *registers;
		port_run_palette_command_private(&state, memory);
		*registers = state.registers;
	}
}
