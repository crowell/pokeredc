#include "port_state.h"

/*
 * Port of PlaceString in home/text.asm.
 *
 * Copies the text string at [DE] into the buffer at [HL], honoring the
 * text-control tokens the original engine interprets. The destination and
 * source are absolute Game Boy addresses (the flat memory model). The
 * terminator is the text-end marker ('@' = $50).
 *
 * Implemented control flow:
 *   - $50 TX_END        : stop
 *   - $4e TX_NEXT       : advance destination by one/two screen rows
 *   - $4f TX_LINE       : move destination to the bottom text row
 *   - the simple name-substitution tokens (PLAYER, RIVAL, #, PKMN, PC, TM,
 *     TRAINER, ROCKET, the six-dots, TARGET, USER) emit their expansion inline
 *   - the screen-command tokens (PARA, PAGE, _CONT, SCROLL, CONT, PROMPT,
 *     DEXEND, DONE, NULL) advance/terminate the destination as the engine does;
 *     the associated screen clears/scrolls are out of scope for the flat model
 *     and are approximated by the destination-pointer movement (the only
 *     observable effect needed by the text-placement contract).
 */

#define SCREEN_WIDTH 20
#define W_TILE_MAP   0xc3a0

#define TX_NULL    0x00
#define TX_PAGE    0x49
#define TX_PKMN    0x4a
#define TX__CONT   0x4b
#define TX_SCROLL  0x4c
#define TX_NEXT    0x4e
#define TX_LINE    0x4f
#define TX_END     0x50
#define TX_PARA    0x51
#define TX_PLAYER  0x52
#define TX_RIVAL   0x53
#define TX_POUND   0x54
#define TX_CONT    0x55
#define TX_SIXDOTS 0x56
#define TX_DONE    0x57
#define TX_PROMPT  0x58
#define TX_TARGET  0x59
#define TX_USER    0x5a
#define TX_PC      0x5b
#define TX_TM      0x5c
#define TX_TRAINER 0x5d
#define TX_ROCKET  0x5e
#define TX_DEXEND  0x5f

#define H_UI_LAYOUT_FLAGS    0xfff6
#define BIT_SINGLE_SPACED_LINES 2
#define H_WHOSE_TURN         0xfff3

#define W_PLAYER_NAME      0xd158
#define W_RIVAL_NAME       0xd34a
#define W_BATTLE_MON_NICK  0xd009
#define W_ENEMY_MON_NICK   0xcfda
#define TEXT_ID_ERROR_PREV 0x19f3
#define DONE_TEXT_PREV     0x1ab2

static void
ps_emit(port_u8 *memory, port_u16 *dest, port_u8 b)
{
	memory[*dest] = b;
	*dest = (port_u16)(*dest + 1);
}

/* Copy a name buffer into the destination until the text-end marker. The live
 * name buffers are '@'-terminated (or padded), so the copy stops cleanly. */
static void
ps_copy_name(port_u8 *memory, port_u16 *dest, port_u16 src_buf)
{
	port_u16 s = src_buf;
	port_u8 b;
	for (;;) {
		b = memory[s];
		if (b == TX_END)
			break;
		ps_emit(memory, dest, b);
		s = (port_u16)(s + 1);
	}
}

static void
ps_copy_enemy_name(port_u8 *memory, port_u16 *dest)
{
	static const port_u8 enemy[] = {0x84, 0xad, 0xa4, 0xac, 0xb8, 0x7f};
	for (unsigned int i = 0; i < sizeof(enemy); ++i)
		ps_emit(memory, dest, enemy[i]);
	ps_copy_name(memory, dest, W_ENEMY_MON_NICK);
}

static port_u16
ps_coord(port_u8 x, port_u8 y)
{
	return (port_u16)(W_TILE_MAP + (port_u16)y * SCREEN_WIDTH + x);
}

__attribute__((noinline, used)) void
port_place_string(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 dest = (port_u16)(((port_u16)state->h << 8) | state->l);
	port_u16 saved_hl = dest;
	port_u16 src = (port_u16)(((port_u16)state->d << 8) | state->e);
	port_u8 c;

	for (;;) {
		c = memory[src];
		state->a = c;
		if (c == TX_END) {
			state->a = c;
			state->b = (port_u8)(dest >> 8);
			state->c = (port_u8)dest;
			state->d = (port_u8)(src >> 8);
			state->e = (port_u8)src;
			state->h = (port_u8)(saved_hl >> 8);
			state->l = (port_u8)saved_hl;
			state->f = PORT_FLAG_N | PORT_FLAG_Z;
			break;
		}

		if (c == TX_NEXT) {
			port_u16 adv = (port_u16)(2 * SCREEN_WIDTH);
			if (memory[H_UI_LAYOUT_FLAGS] &
				(1u << BIT_SINGLE_SPACED_LINES))
				adv = SCREEN_WIDTH;
			dest = (port_u16)(dest + adv);
			saved_hl = dest;
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX_LINE) {
			dest = ps_coord(1, 16);
			saved_hl = dest;
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX_PARA) {
			memory[ps_coord(18, 16)] = 0xee; /* '▼' */
			dest = ps_coord(1, 14);
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX_PAGE) {
			memory[ps_coord(18, 16)] = 0xee;
			dest = ps_coord(1, 11);
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX__CONT) {
			memory[ps_coord(18, 16)] = 0xee;
			dest = ps_coord(1, 16);
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX_SCROLL) {
			dest = ps_coord(1, 16);
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX_CONT) {
			dest = ps_coord(1, 16);
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX_PROMPT) {
			memory[ps_coord(18, 16)] = 0xee;
			memory[ps_coord(18, 16)] = 0x7f;
			state->a = 0x7f;
			state->h = (port_u8)(saved_hl >> 8);
			state->l = (port_u8)saved_hl;
			state->d = (port_u8)(DONE_TEXT_PREV >> 8);
			state->e = (port_u8)DONE_TEXT_PREV;
			break; /* falls through into DoneText (terminate) */
		}
		if (c == TX_DONE) {
			state->h = (port_u8)(saved_hl >> 8);
			state->l = (port_u8)saved_hl;
			state->d = (port_u8)(DONE_TEXT_PREV >> 8);
			state->e = (port_u8)DONE_TEXT_PREV;
			state->f = PORT_FLAG_N | PORT_FLAG_Z;
			break;
		}
		if (c == TX_DEXEND) {
			memory[dest] = 0xe8; /* '.'; PlaceDexEnd does not advance HL */
			state->h = (port_u8)(saved_hl >> 8);
			state->l = (port_u8)saved_hl;
			state->f = PORT_FLAG_N | PORT_FLAG_Z;
			break;
		}
		if (c == TX_NULL) {
			state->b = (port_u8)(dest >> 8);
			state->c = (port_u8)dest;
			state->h = (port_u8)(saved_hl >> 8);
			state->l = (port_u8)saved_hl;
			state->d = (port_u8)(TEXT_ID_ERROR_PREV >> 8);
			state->e = (port_u8)TEXT_ID_ERROR_PREV;
			state->f = PORT_FLAG_H | PORT_FLAG_Z;
			break; /* debug leftover: original prints an error */
		}
		if (c == TX_PLAYER) {
			ps_copy_name(memory, &dest, W_PLAYER_NAME);
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX_RIVAL) {
			ps_copy_name(memory, &dest, W_RIVAL_NAME);
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX_POUND) { /* # -> "POKé" */
			ps_emit(memory, &dest, 0x8f);
			ps_emit(memory, &dest, 0x8e);
			ps_emit(memory, &dest, 0x8a);
			ps_emit(memory, &dest, 0xba);
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX_PKMN) { /* "<PK><MN>" */
			ps_emit(memory, &dest, 0xe1);
			ps_emit(memory, &dest, 0xe2);
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX_PC) { /* "PC" */
			ps_emit(memory, &dest, 0x8f);
			ps_emit(memory, &dest, 0x82);
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX_TM) { /* "TM" */
			ps_emit(memory, &dest, 0x93);
			ps_emit(memory, &dest, 0x8c);
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX_TRAINER) { /* "TRAINER" */
			ps_emit(memory, &dest, 0x93);
			ps_emit(memory, &dest, 0x91);
			ps_emit(memory, &dest, 0x80);
			ps_emit(memory, &dest, 0x88);
			ps_emit(memory, &dest, 0x8d);
			ps_emit(memory, &dest, 0x84);
			ps_emit(memory, &dest, 0x91);
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX_ROCKET) { /* "ROCKET" */
			ps_emit(memory, &dest, 0x91);
			ps_emit(memory, &dest, 0x8e);
			ps_emit(memory, &dest, 0x82);
			ps_emit(memory, &dest, 0x8a);
			ps_emit(memory, &dest, 0x84);
			ps_emit(memory, &dest, 0x93);
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX_SIXDOTS) { /* "……" (two ellipsis glyphs) */
			ps_emit(memory, &dest, 0x75);
			ps_emit(memory, &dest, 0x75);
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX_TARGET) {
			port_u8 t = (port_u8)(memory[H_WHOSE_TURN] ^ 1);
			if (t == 0)
				ps_copy_name(memory, &dest, W_BATTLE_MON_NICK);
			else
				ps_copy_enemy_name(memory, &dest);
			src = (port_u16)(src + 1);
			continue;
		}
		if (c == TX_USER) {
			port_u8 t = memory[H_WHOSE_TURN];
			if (t == 0)
				ps_copy_name(memory, &dest, W_BATTLE_MON_NICK);
			else
				ps_copy_enemy_name(memory, &dest);
			src = (port_u16)(src + 1);
			continue;
		}

		/* Ordinary character: copy verbatim and advance both pointers. */
		ps_emit(memory, &dest, c);
		src = (port_u16)(src + 1);
	}
}
