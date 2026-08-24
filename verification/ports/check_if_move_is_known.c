#include "port_state.h"

/* Port of CheckIfMoveIsKnown in engine/items/tmhm.asm:
 *
 *   ld a, [wWhichPokemon] / ld hl, wPartyMon1Moves / ld bc, PARTYMON_STRUCT_LENGTH
 *   call AddNTimes              ; proven: HL += A*BC
 *   ld a, [wMoveNum] / ld b, a / ld c, NUM_MOVES
 * .loop:
 *   ld a, [hli] / cp b / jr z, .alreadyKnown / dec c / jr nz, .loop
 *   and a / ret                 ; not known: Z from the last move byte
 * .alreadyKnown:
 *   ld hl, AlreadyKnowsText / call PrintText / scf / ret
 *
 * cp leaves Z from equality, N set, H on low-nibble borrow, C when the move
 * is smaller; `dec c` keeps C and adds Z/N/H. `scf` sets C and clears H/N
 * while preserving Z. */

void port_add_n_times(struct cpu_register_state *);
void port_print_text(struct cpu_register_state *, port_u8 *);

#define W_WHICH_POKEMON 0xcf92u
#define W_PARTY_MON1_MOVES 0xd173u
#define W_MOVE_NUM 0xd0e0u
#define PARTYMON_STRUCT_LENGTH 0x2cu
#define NUM_MOVES 4u
#define ALREADY_KNOWS_TEXT_HL 0x7e3bu

__attribute__((noinline, used)) void
port_check_if_move_is_known(struct cpu_register_state *state,
	port_u8 *memory)
{
	port_u16 hl;

	state->a = memory[W_WHICH_POKEMON];
	state->h = (port_u8)(W_PARTY_MON1_MOVES >> 8);
	state->l = (port_u8)(W_PARTY_MON1_MOVES & 0xff);
	state->b = (port_u8)(PARTYMON_STRUCT_LENGTH >> 8);
	state->c = (port_u8)(PARTYMON_STRUCT_LENGTH & 0xff);
	port_add_n_times(state);

	state->a = memory[W_MOVE_NUM];
	state->b = state->a;
	state->c = NUM_MOVES;
	hl = (port_u16)(((port_u16)state->h << 8) | state->l);

	for (;;) {
		port_u8 move = memory[hl];
		port_u8 equal = (port_u8)(move == state->b);
		port_u8 old = state->c;

		hl++;
		state->a = move;
		state->f = (port_u8)((equal ? PORT_FLAG_Z : 0) | PORT_FLAG_N |
		    (((move & 0x0f) < (state->b & 0x0f)) ? PORT_FLAG_H : 0) |
		    ((move < state->b) ? PORT_FLAG_C : 0));
		if (equal) {
			state->h = (port_u8)(ALREADY_KNOWS_TEXT_HL >> 8);
			state->l = (port_u8)(ALREADY_KNOWS_TEXT_HL & 0xff);
			port_print_text(state, memory);
			/* scf */
			state->f = (port_u8)((state->f & PORT_FLAG_Z) |
			    PORT_FLAG_C);
			return;
		}
		state->c = (port_u8)(old - 1u);
		state->f = (port_u8)((state->f & PORT_FLAG_C) | PORT_FLAG_N |
		    ((state->c == 0) ? PORT_FLAG_Z : 0) |
		    (((old & 0x0f) == 0x0f) ? PORT_FLAG_H : 0));
		if (state->c == 0)
			break;
	}
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)(hl & 0xff);
	/* and a */
	state->f = (port_u8)(PORT_FLAG_H | ((state->a == 0) ? PORT_FLAG_Z : 0));
}
