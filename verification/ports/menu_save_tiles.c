#include "port_state.h"

void port_update_sprites(struct cpu_register_state *, port_u8 *);

static void
menu_dec(struct cpu_register_state *registers, port_u8 *value)
{
	port_u8 old = *value;

	(*value)--;
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_N;
	if (*value == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
menu_add_hl(struct cpu_register_state *registers, port_u16 right)
{
	port_u16 left = (port_u16)(((port_u16)registers->h << 8) | registers->l);
	unsigned long result = (unsigned long)left + right;

	registers->f &= PORT_FLAG_Z;
	if ((left & 0x0fff) + (right & 0x0fff) > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if (result > 0xffff)
		registers->f |= PORT_FLAG_C;
	registers->h = (port_u8)(result >> 8);
	registers->l = (port_u8)result;
}

__attribute__((noinline, used)) void
port_two_option_menu_save_screen_tiles_begin(struct menu_save_tiles_state *state)
{
	state->registers.d = 0xce;
	state->registers.e = 0xe9;
	state->registers.b = 5;
	state->registers.c = 6;
}

__attribute__((noinline, used)) port_u8
port_two_option_menu_save_screen_tiles_byte(struct menu_save_tiles_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);

	state->registers.a = state->fetched;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->written = state->registers.a;
	de++;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	menu_dec(&state->registers, &state->registers.c);
	return state->registers.c == 0;
}

__attribute__((noinline, used)) port_u8
port_two_option_menu_save_screen_tiles_row(struct menu_save_tiles_state *state)
{
	menu_add_hl(&state->registers, 14);
	state->registers.c = 6;
	menu_dec(&state->registers, &state->registers.b);
	return state->registers.b == 0;
}

/* Port of TwoOptionMenu_SaveScreenTiles in engine/menus/text_box.asm. */
__attribute__((noinline, used)) void
port_two_option_menu_save_screen_tiles(struct menu_save_tiles_state *state,
	port_u8 memory[65536])
{
	port_u16 hl;
	port_u16 de;

	port_two_option_menu_save_screen_tiles_begin(state);
	for (;;) {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		de = (port_u16)(((port_u16)state->registers.d << 8) |
			state->registers.e);
		state->fetched = memory[hl];
		port_two_option_menu_save_screen_tiles_byte(state);
		memory[de] = state->written;
		if (state->registers.c != 0)
			continue;
		if (port_two_option_menu_save_screen_tiles_row(state))
			return;
	}
}

/* Port of TwoOptionMenu_RestoreScreenTiles in engine/menus/text_box.asm. */
__attribute__((noinline, used)) void
port_two_option_menu_restore_screen_tiles(struct menu_save_tiles_state *state,
	port_u8 memory[65536])
{
	port_u16 hl;
	port_u16 de;

	/* The restore routine has the same 5x6 traversal as the save routine,
	 * with the source and destination pointers exchanged. */
	state->registers.d = 0xce;
	state->registers.e = 0xe9;
	state->registers.b = 5;
	state->registers.c = 6;
	for (;;) {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		de = (port_u16)(((port_u16)state->registers.d << 8) |
			state->registers.e);
		state->fetched = memory[de];
		state->registers.a = state->fetched;
		de++;
		state->registers.d = (port_u8)(de >> 8);
		state->registers.e = (port_u8)de;
		memory[hl] = state->registers.a;
		state->written = state->registers.a;
		hl++;
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
		menu_dec(&state->registers, &state->registers.c);
		if (state->registers.c != 0)
			continue;

		/* push bc / ld bc,SCREEN_WIDTH-6 / add hl,bc / pop bc */
		menu_add_hl(&state->registers, 14);
		state->registers.c = 6;
		menu_dec(&state->registers, &state->registers.b);
		if (state->registers.b == 0)
			break;
	}

	/* The assembly tail calls the public sprite-update wrapper. */
	port_update_sprites(&state->registers, memory);
}
