#include "port_state.h"

/* Port of Route11Gate2FScriptEnd in scripts/Route11Gate2F.asm:
 *
 *   jp TextScriptEnd
 */

void port_text_script_end(struct cpu_register_state *);

__attribute__((noinline, used)) void
port_route11_gate2f_script_end(struct cpu_register_state *state)
{
	port_text_script_end(state);
}
