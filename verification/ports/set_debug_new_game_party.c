#include "port_state.h"

/* Port of SetDebugNewGameParty in engine/debug/debug_party.asm.
 *
 * Walks the DebugNewGameParty ROM table (species, level pairs terminated by
 * $FF) and, for each entry, stores the species/level in wCurPartySpecies /
 * wCurEnemyLevel and adds the mon to the party (via AddPartyMon). The C port
 * reads the table from ROM at its absolute address and reproduces the
 * observable party state: the per-entry wCurPartySpecies / wCurEnemyLevel
 * writes and the deterministic party-append (party count + species list).
 * The full per-mon data initialization (stats, DVs, moves, exp) is performed
 * by _AddPartyMon, which is not ported here; only the observable party-append
 * (wPartyCount increment + wPartySpecies entry) is modeled. The equivalence
 * proof for SetDebugNewGameParty is pending. */

#define W_CUR_PARTY_SPECIES 0xcf91u
#define W_CUR_ENEMY_LEVEL   0xd127u
#define W_PARTY_COUNT       0xd163u
#define W_PARTY_SPECIES     0xd164u
#define DEBUG_NEW_GAME_PARTY 0x64dfu

/* Deterministic observable of AddPartyMon: append the current
 * wCurPartySpecies to the party (bounded at 6 mons). */
static void
add_party_mon(port_u8 *memory)
{
	port_u8 count = memory[W_PARTY_COUNT];
	if (count >= 6)
		return;
	memory[W_PARTY_SPECIES + count] = memory[W_CUR_PARTY_SPECIES];
	memory[W_PARTY_COUNT] = (port_u8)(count + 1);
}

__attribute__((noinline, used)) void
port_set_debug_new_game_party(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 de = DEBUG_NEW_GAME_PARTY;

	(void)state;

	for (;;) {
		port_u8 species = memory[de];
		if (species == (port_u8)0xff)
			return;                         /* cp -1; ret z */
		memory[W_CUR_PARTY_SPECIES] = species;  /* ld [wCurPartySpecies], a */
		de++;
		memory[W_CUR_ENEMY_LEVEL] = memory[de]; /* ld [wCurEnemyLevel], a */
		de++;
		add_party_mon(memory);                   /* call AddPartyMon */
	}
}
