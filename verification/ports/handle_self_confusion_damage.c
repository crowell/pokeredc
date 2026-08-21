#include "port_state.h"

/* Port of HandleSelfConfusionDamage through the HurtItselfText PrintText call. */
__attribute__((noinline, used)) void
port_handle_self_confusion_damage(struct cpu_register_state *registers)
{
	registers->h = 0x5a;
	registers->l = 0x65;
}
