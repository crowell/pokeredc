#include "port_state.h"

/* Port of DoSpecialEffectByAnimationId.done after IsInArray reports no match. */
__attribute__((noinline, used)) void
port_do_special_effect_no_match(struct cpu_register_state *state)
{
	/* The assembly restores the saved BC/DE/HL and leaves AF unchanged. */
	(void)state;
}
