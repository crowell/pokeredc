#include "port_state.h"

static port_u8
add_bytes(struct cpu_register_state *registers, port_u8 left, port_u8 right)
{
	port_u16 wide = (port_u16)left + right;
	port_u8 result = (port_u8)wide;

	registers->f = 0;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xff)
		registers->f |= PORT_FLAG_C;
	return result;
}

__attribute__((noinline, used)) void
port_update_intro_nidorino_oam_begin(struct intro_nidorino_oam_state *state)
{
	state->registers.h = 0xc3;
	state->registers.l = 0x00;
	state->registers.a = state->base_tile;
	state->registers.d = state->registers.a;
}

__attribute__((noinline, used)) port_u8
port_update_intro_nidorino_oam_step(struct intro_nidorino_oam_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 old_c;

	state->registers.a = state->base_y;
	state->registers.a = add_bytes(&state->registers,
		state->registers.a, state->fetched_y);
	state->written_y = state->registers.a;
	hl++;
	state->registers.a = state->base_x;
	state->registers.a = add_bytes(&state->registers,
		state->registers.a, state->fetched_x);
	state->written_x = state->registers.a;
	hl++;
	state->registers.a = state->registers.d;
	state->written_tile = state->registers.a;
	hl = (port_u16)(hl + 2);
	state->registers.d++;
	old_c = state->registers.c;
	state->registers.c--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return state->registers.c == 0;
}

/* Port of UpdateIntroNidorinoOAM in engine/movie/intro.asm. */
__attribute__((noinline, used)) void
port_update_intro_nidorino_oam(struct intro_nidorino_oam_state *state)
{
	port_u16 hl;
	port_u16 offset;

	port_update_intro_nidorino_oam_begin(state);
	do {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		offset = (port_u16)(hl - 0xc300);
		state->fetched_y = state->oam[offset];
		state->fetched_x = state->oam[offset + 1];
		port_update_intro_nidorino_oam_step(state);
		state->oam[offset] = state->written_y;
		state->oam[offset + 1] = state->written_x;
		state->oam[offset + 2] = state->written_tile;
	} while (state->registers.c != 0);
}

__attribute__((noinline, used)) void
port_write_pokeball_oam_data_begin(struct pokeball_oam_state *state)
{
	state->registers.d = 0xce;
	state->registers.e = 0xe9;
	state->registers.c = 6;
}

__attribute__((noinline, used)) port_u8
port_write_pokeball_oam_data_step(struct pokeball_oam_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u8 old_c;

	state->registers.a = state->base_y;
	state->written_y = state->registers.a;
	hl++;
	state->registers.a = state->base_x;
	state->written_x = state->registers.a;
	hl++;
	state->registers.a = state->fetched_tile;
	state->written_tile = state->registers.a;
	hl++;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->written_attributes = state->registers.a;
	hl++;
	state->registers.a = state->base_x;
	state->registers.b = state->registers.a;
	state->registers.a = state->offset_x;
	state->registers.a = add_bytes(&state->registers,
		state->registers.a, state->registers.b);
	state->base_x = state->registers.a;
	de++;
	old_c = state->registers.c;
	state->registers.c--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	return state->registers.c == 0;
}

/* Port of WritePokeballOAMData in engine/battle/draw_hud_pokeball_gfx.asm. */
__attribute__((noinline, used)) void
port_write_pokeball_oam_data(struct pokeball_oam_state *state)
{
	port_u8 index = 0;
	port_u8 output = 0;

	port_write_pokeball_oam_data_begin(state);
	do {
		state->fetched_tile = state->buffer[index++];
		port_write_pokeball_oam_data_step(state);
		state->oam[output++] = state->written_y;
		state->oam[output++] = state->written_x;
		state->oam[output++] = state->written_tile;
		state->oam[output++] = state->written_attributes;
	} while (state->registers.c != 0);
}

__attribute__((noinline, used)) void
port_vermilion_dock_smoke_drift_begin(struct smoke_drift_state *state)
{
	port_u8 swapped;

	state->saved_b = state->registers.b;
	state->saved_c = state->registers.c;
	state->saved_d = state->registers.d;
	state->saved_e = state->registers.e;
	state->registers.h = 0xc3;
	state->registers.l = 0x11;
	state->registers.a = state->drift_amount;
	swapped = (port_u8)((state->registers.a << 4) |
		(state->registers.a >> 4));
	state->registers.a = swapped;
	state->registers.f = swapped == 0 ? PORT_FLAG_Z : 0;
	state->registers.c = state->registers.a;
	state->registers.d = 0;
	state->registers.e = 4;
}

__attribute__((noinline, used)) port_u8
port_vermilion_dock_smoke_drift_step(struct smoke_drift_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u16 sum = (port_u16)(hl + de);
	port_u8 old_c = state->registers.c;

	state->written = (port_u8)(state->fetched + 2);
	state->registers.c--;
	state->registers.f = PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	if ((unsigned long)hl + de > 0xffff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.h = (port_u8)(sum >> 8);
	state->registers.l = (port_u8)sum;
	return state->registers.c == 0;
}

__attribute__((noinline, used)) void
port_vermilion_dock_smoke_drift_finish(struct smoke_drift_state *state)
{
	state->registers.d = state->saved_d;
	state->registers.e = state->saved_e;
	state->registers.b = state->saved_b;
	state->registers.c = state->saved_c;
}

/* Port of VermilionDock_AnimSmokePuffDriftRight in scripts/VermilionDock.asm. */
__attribute__((noinline, used)) void
port_vermilion_dock_smoke_drift(struct smoke_drift_state *state)
{
	port_u16 hl;
	port_u16 offset;

	port_vermilion_dock_smoke_drift_begin(state);
	do {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		offset = (port_u16)(hl - 0xc311);
		state->fetched = state->oam[offset];
		port_vermilion_dock_smoke_drift_step(state);
		state->oam[offset] = state->written;
	} while (state->registers.c != 0);
	port_vermilion_dock_smoke_drift_finish(state);
}

__attribute__((noinline, used)) void
port_init_intro_nidorino_oam_begin(struct init_intro_oam_state *state)
{
	state->registers.h = 0xc3;
	state->registers.l = 0x00;
	state->registers.d = 0;
}

__attribute__((noinline, used)) void
port_init_intro_nidorino_oam_row_begin(struct init_intro_oam_state *state)
{
	state->saved_b = state->registers.b;
	state->saved_c = state->registers.c;
	state->registers.a = state->base_y;
	state->registers.e = state->registers.a;
}

__attribute__((noinline, used)) port_u8
port_init_intro_nidorino_oam_inner_step(struct init_intro_oam_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 old_c;

	state->registers.a = state->registers.e;
	state->registers.a = add_bytes(&state->registers,
		state->registers.a, 8);
	state->registers.e = state->registers.a;
	state->written_y = state->registers.a;
	hl++;
	state->registers.a = state->base_x;
	state->written_x = state->registers.a;
	hl++;
	state->registers.a = state->registers.d;
	state->written_tile = state->registers.a;
	hl++;
	state->registers.a = 0x80;
	state->written_attributes = state->registers.a;
	hl++;
	state->registers.d++;
	old_c = state->registers.c;
	state->registers.c--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return state->registers.c == 0;
}

__attribute__((noinline, used)) port_u8
port_init_intro_nidorino_oam_row_finish(struct init_intro_oam_state *state)
{
	port_u8 old_b;

	state->registers.a = state->base_x;
	state->registers.a = add_bytes(&state->registers,
		state->registers.a, 8);
	state->base_x = state->registers.a;
	state->registers.b = state->saved_b;
	state->registers.c = state->saved_c;
	old_b = state->registers.b;
	state->registers.b--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.b == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_b & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.b == 0;
}

/* Port of InitIntroNidorinoOAM in engine/movie/intro.asm. */
__attribute__((noinline, used)) void
port_init_intro_nidorino_oam(
	struct init_intro_oam_state *state, port_u8 *memory)
{
	port_u16 hl;

	port_init_intro_nidorino_oam_begin(state);
	do {
		port_init_intro_nidorino_oam_row_begin(state);
		do {
			hl = (port_u16)(((port_u16)state->registers.h << 8) |
				state->registers.l);
			port_init_intro_nidorino_oam_inner_step(state);
			memory[hl++] = state->written_y;
			memory[hl++] = state->written_x;
			memory[hl++] = state->written_tile;
			memory[hl] = state->written_attributes;
		} while (state->registers.c != 0);
	} while (!port_init_intro_nidorino_oam_row_finish(state));
}
