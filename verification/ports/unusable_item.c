#include "port_state.h"

/* Port of UnusableItem in engine/items/item_effects.asm:
 *
 *   jp ItemUseNotTime
 */

void port_item_use_not_time(struct cpu_register_state *);

__attribute__((noinline, used)) void
port_unusable_item(struct cpu_register_state *state)
{
	port_item_use_not_time(state);
}
