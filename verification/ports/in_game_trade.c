#include "port_state.h"

/* State for InGameTrade_GetReceivedMonPointer in
 * engine/events/in_game_trades.asm: the eight accumulator registers plus the
 * single RAM byte the function reads. */
struct received_mon_pointer_state {
	struct cpu_register_state registers; /* a,f,b,c,d,e,h,l at 0-7 */
	port_u8 w_party_count;                /* at 8 */
};

port_u8 port_add_n_times_begin(struct cpu_register_state *state);
port_u8 port_add_n_times_step(struct cpu_register_state *state);
void port_copy_data(struct cpu_register_state *state, port_u8 *memory);

/* Load the current party count, decrement it, and prime AddNTimes. When the
 * count is zero after the decrement the loop body never runs and the resulting
 * pointer is copied to DE immediately. Returns 1 (done) when no iteration is
 * required, otherwise 0 (continue). */
__attribute__((noinline, used)) port_u8
port_in_game_trade_get_received_mon_pointer_begin(
	struct received_mon_pointer_state *state)
{
	state->registers.a = (port_u8)(state->w_party_count - 1);
	if (port_add_n_times_begin(&state->registers)) {
		state->registers.e = state->registers.l;
		state->registers.d = state->registers.h;
		return 1;
	}
	return 0;
}

/* Run a single AddNTimes iteration. The resulting pointer is copied to
 * DE by the caller once the loop has finished. */
__attribute__((noinline, used)) port_u8
port_in_game_trade_get_received_mon_pointer_step(
	struct received_mon_pointer_state *state)
{
	return port_add_n_times_step(&state->registers);
}

/* Port of InGameTrade_GetReceivedMonPointer in engine/events/in_game_trades.asm.
 *
 * The routine loads the current party count, decrements it, adds BC to HL that
 * many times through AddNTimes, and copies the resulting pointer into DE. */
__attribute__((noinline, used)) void
port_in_game_trade_get_received_mon_pointer(
	struct received_mon_pointer_state *state)
{
	if (port_in_game_trade_get_received_mon_pointer_begin(state))
		return;
	while (!port_in_game_trade_get_received_mon_pointer_step(state))
		;
	state->registers.e = state->registers.l;
	state->registers.d = state->registers.h;
}

/* Port of InGameTrade_CopyData in engine/events/in_game_trades.asm.
 *
 * The routine merely pushes HL and BC, calls CopyData, and pops them back, so
 * HL and BC are preserved while DE is left advanced past the destination (since
 * CopyData itself mutates HL/DE/BC). */
__attribute__((noinline, used)) void
port_in_game_trade_copy_data(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 saved_h = state->h;
	port_u8 saved_l = state->l;
	port_u8 saved_b = state->b;
	port_u8 saved_c = state->c;

	port_copy_data(state, memory);

	state->h = saved_h;
	state->l = saved_l;
	state->b = saved_b;
	state->c = saved_c;
}
