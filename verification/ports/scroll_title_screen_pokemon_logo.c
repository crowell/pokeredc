#include "port_state.h"

void port_delay_frame(struct delay_frame_state *, const port_u8 *);

static void
title_logo_add_d(struct cpu_register_state *registers)
{
	port_u8 left = registers->a;
	port_u8 right = registers->d;
	port_u16 result = (port_u16)left + right;

	registers->a = (port_u8)result;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (result > 0xff)
		registers->f |= PORT_FLAG_C;
}

static void
title_logo_dec_e(struct cpu_register_state *registers)
{
	port_u8 old = registers->e;

	registers->e--;
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_N;
	if (registers->e == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
title_logo_delay_frame(struct scroll_title_screen_pokemon_logo_state *state)
{
	static const port_u8 acknowledged_vblank[] = {0};
	struct delay_frame_state delay;

	delay.registers = state->registers;
	delay.vblank_occurred = state->vblank_occurred;
	delay.observed_vblank = state->observed_vblank;
	port_delay_frame(&delay, acknowledged_vblank);
	state->registers = delay.registers;
	state->vblank_occurred = delay.vblank_occurred;
	state->observed_vblank = delay.observed_vblank;
}

/* Port of DisplayTitleScreen.ScrollTitleScreenPokemonLogo in
 * engine/movie/title.asm. */
__attribute__((noinline, used)) void
port_scroll_title_screen_pokemon_logo(
	struct scroll_title_screen_pokemon_logo_state *state)
{
	do {
		title_logo_delay_frame(state);
		state->registers.a = state->scroll_y;
		title_logo_add_d(&state->registers);
		state->scroll_y = state->registers.a;
		title_logo_dec_e(&state->registers);
	} while (state->registers.e != 0);
}
