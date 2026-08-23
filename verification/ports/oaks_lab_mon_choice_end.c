#include "port_state.h"

/* Port of OaksLabMonChoiceEnd in scripts/OaksLab.asm:
 *
 *   jp TextScriptEnd
 */

void port_text_script_end(struct cpu_register_state *);

__attribute__((noinline, used)) void
port_oaks_lab_mon_choice_end(struct cpu_register_state *state)
{
	port_text_script_end(state);
}
