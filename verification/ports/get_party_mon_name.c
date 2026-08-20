#include "port_state.h"

struct get_party_mon_name_state {
    struct cpu_register_state registers;
    port_u8 source[11];
    port_u8 destination[11];
    port_u8 copy_a;
    port_u8 copy_f;
};

/* Port of GetPartyMonName in home/pokemon.asm.
 *
 * SkipFixedLengthTextEntries and CopyData are compositional boundaries. The
 * explicit 11-byte name state records the copy, while the balanced PUSH/POP
 * sequence restores caller BC/DE/HL and CopyData's A/F result is explicit. */

__attribute__((noinline, used)) void
port_get_party_mon_name(struct get_party_mon_name_state *state)
{
    for (int i = 0; i < 11; i++)
        state->destination[i] = state->source[i];
    state->registers.a = state->copy_a;
    state->registers.f = state->copy_f;
}
