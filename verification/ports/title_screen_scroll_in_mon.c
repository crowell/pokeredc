#include "port_state.h"

void port_title_scroll(struct title_scroll_body_state *,
	const port_u8 *, const port_u8 *, const port_u8 *,
	const struct title_scroll_scanline_timing *);

/* Port of TitleScreenScrollInMon in engine/movie/title.asm. */
__attribute__((noinline, used)) void
port_title_screen_scroll_in_mon(
	struct title_screen_scroll_in_mon_state *state,
	const port_u8 *in_table, const port_u8 *out_table,
	const port_u8 *title_ball_y_table,
	const struct title_scroll_scanline_timing *timings)
{
	struct cpu_register_state *registers = &state->scroll.registers;
	port_u8 saved_bank = state->loaded_rom_bank;
	port_u8 saved_f = registers->f;

	registers->d = 0;
	registers->b = 0x0d;
	registers->h = 0x72;
	registers->l = 0x58;

	/* Bankswitch entry and the return address consumed by TitleScroll. */
	registers->a = state->loaded_rom_bank;
	registers->a = registers->b;
	state->loaded_rom_bank = registers->a;
	state->mapper_bank = registers->a;
	registers->b = 0x35;
	registers->c = 0xe4;
	port_title_scroll(&state->scroll, in_table, out_table,
		title_ball_y_table, timings);

	/* Bankswitch.Return pops the saved AF into BC and restores its bank. */
	registers->b = saved_bank;
	registers->c = saved_f;
	registers->a = registers->b;
	state->loaded_rom_bank = registers->a;
	state->mapper_bank = registers->a;

	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	state->wy = registers->a;
}
