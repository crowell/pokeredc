#include "port_state.h"

#define W_ADDED_TO_PARTY                 0xccd3
#define W_PARTY_COUNT                    0xd163
#define W_BOX_COUNT                      0xda80
#define W_ENEMY_BATTLE_STATUS3          0xd069
#define W_ENEMY_MON_SPECIES2            0xcfd8
#define W_CURRENT_BOX_NUM               0xd5a0
#define W_STRING_BUFFER                 0xcf4b
#define W_DO_NOT_WAIT                   0xcc3c
#define W_CUR_PARTY_SPECIES             0xcf91
#define PARTY_LENGTH                    6
#define MONS_PER_BOX                    20
#define BOX_NUM_MASK                    0x7f

/* Port of _GivePokemon in engine/events/give_pokemon.asm (the real routine
 * reached through the `farjp _GivePokemon` wrapper in home/give.asm).
 *
 * Based on the current party and box counts it decides whether the mon is
 * added to the party (wAddedToParty = 1, carry set, wDoNotWait... = 1), sent to
 * the box (wEnemyBattleStatus3 cleared, wEnemyMonSpecies2 set, box-number text
 * written to wStringBuffer, carry set), or rejected because the box is full
 * (carry cleared). The called subroutines (SetPokedexOwnedFlag, AddPartyMon,
 * SendNewMonToBox, LoadEnemyMonData, PrintText and the predefs) are
 * compositional boundaries and are not inlined here. */

struct give_pokemon_state {
	port_u8 f; /* carry observable: PORT_FLAG_C = success, 0 = box full */
};

__attribute__((noinline, used)) void
port_give_pokemon(struct give_pokemon_state *state, port_u8 *memory)
{
	port_u8 party_count = memory[W_PARTY_COUNT];
	port_u8 box_count = memory[W_BOX_COUNT];

	memory[W_ADDED_TO_PARTY] = 0;

	if (party_count < PARTY_LENGTH) {
		/* .addToParty */
		memory[W_ADDED_TO_PARTY] = 1;
		memory[W_DO_NOT_WAIT] = 1;
		state->f = PORT_FLAG_C;
		return;
	}
	if (box_count >= MONS_PER_BOX) {
		/* .boxFull */
		state->f = 0;
		return;
	}
	/* add to box */
	memory[W_ENEMY_BATTLE_STATUS3] = 0;
	memory[W_ENEMY_MON_SPECIES2] = memory[W_CUR_PARTY_SPECIES];
	{
		port_u8 box = (port_u8)(memory[W_CURRENT_BOX_NUM] & BOX_NUM_MASK);
		port_u8 tens = 0;
		port_u8 ones = (port_u8)(box + '1'); /* 1-based box number, ASCII */

		if (box >= 9) {
			tens = '1';
			ones = (port_u8)((box - 9) + '0');
		}
		if (tens != 0) {
			memory[W_STRING_BUFFER] = tens;
			memory[W_STRING_BUFFER + 1] = ones;
			memory[W_STRING_BUFFER + 2] = '@';
		} else {
			memory[W_STRING_BUFFER] = ones;
			memory[W_STRING_BUFFER + 1] = '@';
		}
	}
	state->f = PORT_FLAG_C;
}
