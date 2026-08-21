#include "port_state.h"

/* Port of CalculateModifiedStats through the first CalculateModifiedStat call. */
__attribute__((noinline, used)) void
port_calculate_modified_stats(struct cpu_register_state *registers)
{
	registers->c = 0;
}
