#include "port_state.h"

/*
 * Port of CancelledEvolution in engine/pokemon/evos_moves.asm.
 *
 * Reached via `callfar EvolveMon ; jp c, CancelledEvolution` from inside
 * EvolutionAfterBattle when the player cancels the evolution. Observable
 * behavior: print the "Stopped evolving!" text (pointer in HL) and clear the
 * screen, then return to the party-mon evolution loop.
 *
 * The trailing `pop hl` and `jp Evolution_PartyMonLoop` are control-flow that
 * continues the enclosing loop; in the native port they are modeled as a return
 * (the loop tail is a compositional boundary, not re-modeled here).
 */

__attribute__((noinline, used)) void
port_print_text(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_clear_screen(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_cancelled_evolution(struct cpu_register_state *state, port_u8 *memory)
{
	/* PrintText(StoppedEvolvingText): text pointer is already in HL. */
	port_print_text(state, memory);
	/* ClearScreen */
	port_clear_screen(state, memory);
	/* pop hl ; jp Evolution_PartyMonLoop -> loop tail boundary: return. */
}
