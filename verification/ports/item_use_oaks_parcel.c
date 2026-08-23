#include "port_state.h"

/* Port of ItemUseOaksParcel in engine/items/item_effects.asm:
 *
 *   jp ItemUseNotYoursToUse
 */

void port_item_use_not_yours_to_use(struct cpu_register_state *);

__attribute__((noinline, used)) void
port_item_use_oaks_parcel(struct cpu_register_state *state)
{
	port_item_use_not_yours_to_use(state);
}
