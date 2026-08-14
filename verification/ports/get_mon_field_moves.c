#include "port_state.h"

/* Port of GetMonFieldMoves in engine/menus/text_box.asm.
 *
 * Reads the selected party mon's move list, walks the FieldMoveDisplayData
 * table, and for each move that is a field move appends its name index to
 * wFieldMoves, bumps wNumFieldMoves, records the move id in wLastFieldMoveID,
 * and tracks the leftmost (minimum) x coordinate in
 * wFieldMovesLeftmostXCoord. The FieldMoveDisplayData table is read read-only
 * from ROM; in the flat memory model it is supplied at its ROM address. */

#define W_WHICHPOKEMON 0xcf92u
#define W_PARTY_MON1_MOVES 0xd173u
#define PARTYMON_STRUCT_LENGTH 0x2cu
#define NUM_MOVES 4u
#define W_FIELD_MOVES 0xcd3du
#define W_NUM_FIELD_MOVES 0xcd41u
#define W_FIELD_MOVES_LEFTMOST_XCOORD 0xcd42u
#define W_LAST_FIELD_MOVE_ID 0xcd43u
#define FIELD_MOVE_DISPLAY_DATA 0x7823u

__attribute__((noinline, used)) void
port_get_mon_field_moves(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	port_u8 which = memory[W_WHICHPOKEMON];
	port_u16 hl = W_PARTY_MON1_MOVES
		+ (port_u16)which * PARTYMON_STRUCT_LENGTH;
	port_u16 de = hl;
	port_u8 c = NUM_MOVES + 1;
	port_u16 field_ptr = W_FIELD_MOVES;
	while (1) {
		port_u16 saved_field_ptr = field_ptr; /* push hl */
		c--;                                  /* .nextMove: dec c */
		if (c == 0)
			break;                           /* jr z, .done */
		port_u8 a = memory[de];               /* ld a, [de] */
		de++;
		if (a == 0)
			break;                           /* and a; jr z, .done */
		port_u8 b = a;                        /* ld b, a */
		port_u16 tbl = FIELD_MOVE_DISPLAY_DATA; /* ld hl, FieldMoveDisplayData */
		while (1) {                           /* .fieldMoveLoop */
			port_u8 tbl_move = memory[tbl];   /* ld a, [hli] */
			tbl++;
			if (tbl_move == 0xFF)
				break;                       /* cp $ff; jr z, .nextMove */
			if (tbl_move == b) {              /* cp b; jr z, .foundFieldMove */
				memory[W_LAST_FIELD_MOVE_ID] = b;
				port_u8 name_index = memory[tbl]; /* ld a, [hli] */
				tbl++;
				port_u8 xcoord = memory[tbl];    /* ld b, [hl] */
				tbl++;
				field_ptr = saved_field_ptr;     /* pop hl */
				memory[field_ptr] = name_index;  /* ld [hli], a */
				field_ptr++;
				port_u8 nfm = (port_u8)(memory[W_NUM_FIELD_MOVES] + 1);
				memory[W_NUM_FIELD_MOVES] = nfm;
				port_u8 leftmost = memory[W_FIELD_MOVES_LEFTMOST_XCOORD];
				if (leftmost >= xcoord) {        /* cp b; jr c, .skip */
					memory[W_FIELD_MOVES_LEFTMOST_XCOORD] = xcoord;
				}
				b = memory[W_LAST_FIELD_MOVE_ID];
				break;                           /* jr .loop */
			}
			tbl += 2;                             /* inc hl; inc hl */
		}
	}
	/* .done: pop hl; ret (field_ptr is not observed) */
}
