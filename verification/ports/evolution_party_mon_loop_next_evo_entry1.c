#include "port_state.h"

/* Port of Evolution_PartyMonLoop.nextEvoEntry1 in engine/pokemon/evos_moves.asm.
 *
 * inc hl; inc hl; jp .evoEntryLoop. 16-bit INC and JP preserve F; the local JP is the boundary. */

__attribute__((noinline, used)) void
port_evolution_party_mon_loop_next_evo_entry1(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    port_u16 hl = ((port_u16)state->h << 8) | state->l;
    hl += 2;
    state->h = (port_u8)(hl >> 8);
    state->l = (port_u8)hl;
}
