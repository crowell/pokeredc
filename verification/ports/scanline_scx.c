#include "port_state.h"

static void
scanline_cp(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;

	registers->f = PORT_FLAG_N;
	if (left == right)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) port_u8
port_scanline_scx_wait_for_l(struct scanline_scx_state *state)
{
	state->registers.a = state->ly;
	scanline_cp(&state->registers, state->registers.l);
	return state->registers.a == state->registers.l;
}

__attribute__((noinline, used)) void
port_scanline_scx_store_h(struct scanline_scx_state *state)
{
	state->registers.a = state->registers.h;
	state->scx = state->registers.a;
}

__attribute__((noinline, used)) port_u8
port_scanline_scx_wait_until_not_h(struct scanline_scx_state *state)
{
	state->registers.a = state->ly;
	scanline_cp(&state->registers, state->registers.h);
	return state->registers.a != state->registers.h;
}

static void
scanline_scx_run(struct scanline_scx_state *state,
	const port_u8 *before, const port_u8 *after)
{
	port_u16 index = 0;

	do {
		state->ly = before[index++];
	} while (!port_scanline_scx_wait_for_l(state));
	port_scanline_scx_store_h(state);
	index = 0;
	do {
		state->ly = after[index++];
	} while (!port_scanline_scx_wait_until_not_h(state));
}

/* Port of SetScrollXForSlidingPlayerBodyLeft in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_set_scroll_x_for_sliding_player_body_left(
	struct scanline_scx_state *state, const port_u8 *before,
	const port_u8 *after)
{
	scanline_scx_run(state, before, after);
}

/* Port of ScrollCreditsMonLeft_SetSCX in engine/movie/credits.asm. */
__attribute__((noinline, used)) void
port_scroll_credits_mon_left_set_scx(struct scanline_scx_state *state,
	const port_u8 *before, const port_u8 *after)
{
	scanline_scx_run(state, before, after);
}

/* Port of ScrollTitleScreenGameVersion in engine/movie/title.asm. */
__attribute__((noinline, used)) void
port_scroll_title_screen_game_version(struct scanline_scx_state *state,
	const port_u8 *before, const port_u8 *after)
{
	scanline_scx_run(state, before, after);
}

__attribute__((noinline, used)) void
port_scroll_credits_mon_left_first_setup(struct scanline_scx_state *state)
{
	state->registers.h = state->registers.b;
	state->registers.l = 0x20;
}

__attribute__((noinline, used)) void
port_scroll_credits_mon_left_second_setup(struct scanline_scx_state *state)
{
	state->registers.h = 0;
	state->registers.l = 0x70;
}

__attribute__((noinline, used)) void
port_scroll_credits_mon_left_finish(struct scanline_scx_state *state)
{
	port_u8 left;
	port_u16 result;

	state->registers.a = state->registers.b;
	left = state->registers.a;
	result = (port_u16)left + 8;
	state->registers.a = (port_u8)result;
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) + 8 > 0x0f)
		state->registers.f |= PORT_FLAG_H;
	if (result > 0xff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.b = state->registers.a;
}

/* Port of ScrollCreditsMonLeft in engine/movie/credits.asm. */
__attribute__((noinline, used)) void
port_scroll_credits_mon_left(struct scanline_scx_state *state,
	const port_u8 *before_first, const port_u8 *after_first,
	const port_u8 *before_second, const port_u8 *after_second)
{
	port_scroll_credits_mon_left_first_setup(state);
	scanline_scx_run(state, before_first, after_first);
	port_scroll_credits_mon_left_second_setup(state);
	scanline_scx_run(state, before_second, after_second);
	port_scroll_credits_mon_left_finish(state);
}

__attribute__((noinline, used)) void
port_vermilion_dock_sync_scroll_first_setup(struct scanline_scx_state *state)
{
	state->registers.h = state->registers.d;
	state->registers.l = 0x50;
}

__attribute__((noinline, used)) void
port_vermilion_dock_sync_scroll_second_setup(struct scanline_scx_state *state)
{
	state->registers.h = 0;
	state->registers.l = 0x80;
}

/* Port of VermilionDock_SyncScrollWithLY in scripts/VermilionDock.asm. */
__attribute__((noinline, used)) void
port_vermilion_dock_sync_scroll_with_ly(struct scanline_scx_state *state,
	const port_u8 *before_first, const port_u8 *after_first,
	const port_u8 *before_second, const port_u8 *after_second)
{
	port_vermilion_dock_sync_scroll_first_setup(state);
	scanline_scx_run(state, before_first, after_first);
	port_vermilion_dock_sync_scroll_second_setup(state);
	scanline_scx_run(state, before_second, after_second);
}
