#include "port_state.h"

#define W_LETTER_PRINTING_DELAY_FLAGS 0xd358u
#define W_ENEMY_MON_SPECIES2 0xcfd8u
#define W_TRAINER_CLASS 0xd031u
#define W_AI_COUNT 0xccdfu
#define W_ENEMY_MON_PARTY_POS 0xcfe8u
#define W_IS_IN_BATTLE 0xd057u
#define H_START_TILE_ID 0xffe1u
#define OPP_ID_OFFSET 200u
#define BIT_TEXT_DELAY 1u

/* Port of InitBattleCommon (engine/battle/core.asm).
 *
 * Clears the text-delay flag, then (after the InitBattleVariables callfar
 * boundary) reads wEnemyMonSpecies2 and subtracts OPP_ID_OFFSET. With a carry
 * it is a wild battle (delegate to InitWildBattle, a separate boundary).
 * Otherwise it is a trainer battle: stores the trainer class, zeroes several
 * battle fields, and jumps to _InitBattleCommon. The callfar/ predef/ call
 * tails are explicit boundaries; the deterministic writes below are modeled. */
__attribute__((noinline, used)) void
port_init_battle_common(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	/* res BIT_TEXT_DELAY, [wLetterPrintingDelayFlags] */
	port_u8 flags = memory[W_LETTER_PRINTING_DELAY_FLAGS];
	flags &= (port_u8)~(1u << BIT_TEXT_DELAY);
	memory[W_LETTER_PRINTING_DELAY_FLAGS] = flags;

	/* callfar InitBattleVariables (boundary) */

	/* ld a, [wEnemyMonSpecies2]; sub OPP_ID_OFFSET; jp c, InitWildBattle */
	port_u8 enemy = memory[W_ENEMY_MON_SPECIES2];
	int carry = (enemy < OPP_ID_OFFSET);
	port_u8 trainer_class = (port_u8)(enemy - OPP_ID_OFFSET);
	if (carry) {
		/* InitWildBattle (separate symbol): sets wIsInBattle = 1 and sprite
		 * fields. Not ported here; modeled as a boundary. */
		return;
	}

	/* trainer path */
	memory[W_TRAINER_CLASS] = trainer_class;
	/* GetTrainerInformation / ReadTrainer /
	 * DoBattleTransitionAndInitBattleVariables / _LoadTrainerPic (boundaries) */
	memory[W_ENEMY_MON_SPECIES2] = 0;
	memory[H_START_TILE_ID] = 0;
	memory[W_AI_COUNT] = 0xffu;
	/* predef CopyUncompressedPicToTilemap (boundary) */
	memory[W_ENEMY_MON_PARTY_POS] = 0xffu;
	memory[W_IS_IN_BATTLE] = 0x02u;
	/* jp _InitBattleCommon (boundary) */
}
