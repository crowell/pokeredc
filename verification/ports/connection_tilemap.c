#include "port_state.h"

static port_u16
connection_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
connection_dec(struct cpu_register_state *registers, port_u8 *value)
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
connection_row_begin(struct connection_tilemap_state *state)
{
	state->saved_d = state->registers.d;
	state->saved_e = state->registers.e;
	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;
}

static port_u8
connection_inner_step(struct connection_tilemap_state *state,
	port_u8 *counter)
{
	port_u16 hl = connection_pair(state->registers.h, state->registers.l);
	port_u16 de = connection_pair(state->registers.d, state->registers.e);

	state->registers.a = state->fetched;
	hl++;
	state->written = state->registers.a;
	de++;
	connection_dec(&state->registers, counter);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	return *counter != 0;
}

static void
connection_advance_row(struct connection_tilemap_state *state,
	port_u8 source_width)
{
	port_u16 hl = connection_pair(state->saved_h, state->saved_l);
	port_u16 de = connection_pair(state->saved_d, state->saved_e);
	port_u8 stride = (port_u8)(state->map_width + 6);
	port_u8 source_low = (port_u8)hl;
	port_u8 destination_low = (port_u8)de;
	port_u16 source_sum = (port_u16)source_low + source_width;
	port_u16 destination_sum = (port_u16)destination_low + stride;

	hl = (port_u16)((hl & 0xff00) | (port_u8)source_sum);
	if (source_sum > 0xff)
		hl = (port_u16)(hl + 0x100);
	de = (port_u16)((de & 0xff00) | (port_u8)destination_sum);
	if (destination_sum > 0xff)
		de = (port_u16)(de + 0x100);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.a = (port_u8)destination_sum;
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((destination_low & 0x0f) + (stride & 0x0f) > 0x0f)
		state->registers.f |= PORT_FLAG_H;
	if (destination_sum > 0xff)
		state->registers.f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) void
port_load_north_south_connections_begin(struct connection_tilemap_state *state)
{
	state->registers.c = 3;
}

__attribute__((noinline, used)) void
port_load_north_south_connections_row_begin(
	struct connection_tilemap_state *state)
{
	connection_row_begin(state);
	state->registers.a = state->strip_width;
	state->registers.b = state->registers.a;
}

__attribute__((noinline, used)) port_u8
port_load_north_south_connections_inner_step(
	struct connection_tilemap_state *state)
{
	return connection_inner_step(state, &state->registers.b);
}

__attribute__((noinline, used)) port_u8
port_load_north_south_connections_row_finish(
	struct connection_tilemap_state *state)
{
	connection_advance_row(state, state->north_south_width);
	connection_dec(&state->registers, &state->registers.c);
	return state->registers.c != 0;
}

/* Port of LoadNorthSouthConnectionsTileMap in home/overworld.asm. */
__attribute__((noinline, used)) void
port_load_north_south_connections_tile_map(
	struct connection_tilemap_state *state, port_u8 *memory)
{
	port_u16 source;
	port_u16 destination;

	port_load_north_south_connections_begin(state);
	do {
		port_load_north_south_connections_row_begin(state);
		do {
			source = connection_pair(state->registers.h, state->registers.l);
			destination = connection_pair(state->registers.d, state->registers.e);
			state->fetched = memory[source];
			port_load_north_south_connections_inner_step(state);
			memory[destination] = state->written;
		} while (state->registers.b != 0);
	} while (port_load_north_south_connections_row_finish(state));
}

__attribute__((noinline, used)) void
port_load_east_west_connections_row_begin(
	struct connection_tilemap_state *state)
{
	connection_row_begin(state);
	state->registers.c = 3;
}

__attribute__((noinline, used)) port_u8
port_load_east_west_connections_inner_step(
	struct connection_tilemap_state *state)
{
	return connection_inner_step(state, &state->registers.c);
}

__attribute__((noinline, used)) port_u8
port_load_east_west_connections_row_finish(
	struct connection_tilemap_state *state)
{
	connection_advance_row(state, state->east_west_width);
	connection_dec(&state->registers, &state->registers.b);
	return state->registers.b != 0;
}

/* Port of LoadEastWestConnectionsTileMap in home/overworld.asm. */
__attribute__((noinline, used)) void
port_load_east_west_connections_tile_map(
	struct connection_tilemap_state *state, port_u8 *memory)
{
	port_u16 source;
	port_u16 destination;

	do {
		port_load_east_west_connections_row_begin(state);
		do {
			source = connection_pair(state->registers.h, state->registers.l);
			destination = connection_pair(state->registers.d, state->registers.e);
			state->fetched = memory[source];
			port_load_east_west_connections_inner_step(state);
			memory[destination] = state->written;
		} while (state->registers.c != 0);
	} while (port_load_east_west_connections_row_finish(state));
}
