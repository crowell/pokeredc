#include "port_state.h"

/* Port of KnowsHMMove in engine/pokemon/bills_pc.asm.
 *
 * Returns whether the party mon at index [wWhichPokemon] knows an HM move.
 * The original computes the mon's move-list base with AddNTimes, then for each
 * of its NUM_MOVES walks the list and asks IsInArray against HMMoveArray;
 * it returns the first matching HM move id (in `a`, with carry set) or 0. */

#define KHM_W_PARTY_MON1_MOVES 0xd173u
#define KHM_W_WHICH_POKEMON 0xcf92u
#define KHM_PARTYMON_STRUCT_LENGTH 0x2cu
#define KHM_NUM_MOVES 4u
#define KHM_HM_CUT 0x0fu
#define KHM_HM_FLY 0x13u
#define KHM_HM_SURF 0x39u
#define KHM_HM_STRENGTH 0x46u
#define KHM_HM_FLASH 0x94u

__attribute__((noinline, used)) void
port_knows_hm_move(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 which = memory[KHM_W_WHICH_POKEMON];
	port_u16 base = (port_u16)(
		KHM_W_PARTY_MON1_MOVES +
		(port_u16)(KHM_PARTYMON_STRUCT_LENGTH * which));
	port_u8 i;
	port_u8 last = 0;
	for (i = 0; i < KHM_NUM_MOVES; i++) {
		port_u8 v = memory[base + i];
		last = v;
		/* Branchless "v is one of the five HM ids": the product of
		 * (v - id) over every HM id is zero iff v matches one. A single
		 * comparison keeps the symbolic checker to one fork per move. */
		unsigned long long diff = (unsigned long long)v - 0x0full;
		diff *= (unsigned long long)v - 0x13ull;
		diff *= (unsigned long long)v - 0x39ull;
		diff *= (unsigned long long)v - 0x46ull;
		diff *= (unsigned long long)v - 0x94ull;
		if (diff == 0) {
			state->a = v;
			return;
		}
	}
	/* No HM found: the original falls through to `and a; ret`, leaving `a`
	 * as the last move read (not zeroed). */
	state->a = last;
}
