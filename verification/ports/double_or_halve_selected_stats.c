#include "port_state.h"

extern void port_double_selected_stats(struct selected_stats_state *state,
	port_u8 stats[8]);
extern void port_halve_selected_stats(struct selected_stats_state *state,
	port_u8 stats[8]);

/* Port of DoubleOrHalveSelectedStats: ordered far calls. */
__attribute__((noinline, used)) void
port_double_or_halve_selected_stats(struct selected_stats_state *state,
	port_u8 stats[8])
{
	port_double_selected_stats(state, stats);
	port_halve_selected_stats(state, stats);
}
