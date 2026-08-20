#include "port_state.h"

/*
 * Port of DisplayListMenuID / DisplayListMenuIDLoop in home/list_menu.asm.
 *
 * Displays a scrollable list menu and, on a button press, selects or cancels
 * an entry, recording the chosen item and its name. The assembly is a single
 * iteration of an interactive loop that redisplays and waits for input; this
 * port models one such iteration (one invocation = one loop pass). Sub-calls
 * that are display- or timing-only (DisplayTextBoxID, UpdateSprites,
 * PrintListMenuEntries, LoadGBPal, DelayFrames, Delay3, PlaceMenuCursor,
 * PlaceUnfilledArrowMenuCursor) have no effect on the menu-state memory
 * contract modelled here and are elided. BankswitchHome / BankswitchBack are
 * modelled as the ROM-bank writes they perform. GetItemName performs the full
 * ItemNames decompression only as a best-effort placeholder (the item id byte
 * plus a terminator); the pokemon path copies the genuine party/box nickname.
 * HandleItemListSwapping (SELECT) is deferred. Equivalence is pending.
 */

#define H_AUTO_BG_TRANSFER_ENABLED 0xffba
#define H_JOY7                    0xffb7
#define W_BATTLE_TYPE             0xd05a
#define W_STATUS_FLAGS5           0xd730
#define BIT_NO_TEXT_DELAY         6
#define W_MENU_ITEM_TO_SWAP       0xcc35
#define W_LIST_COUNT              0xd12a
#define W_LIST_POINTER            0xcf8b
#define W_TEXT_BOX_ID             0xd125
#define LIST_MENU_BOX             0x0d
#define W_MENU_WATCH_MOVING_OOB   0xcc37
#define W_MAX_MENU_ITEM           0xcc28
#define W_TOP_MENU_ITEM_Y         0xcc24
#define W_TOP_MENU_ITEM_X         0xcc25
#define W_MENU_WATCHED_KEYS       0xcc29
#define W_LIST_SCROLL_OFFSET      0xcc36
#define W_CURRENT_MENU_ITEM       0xcc26
#define W_LIST_MENU_ID            0xcf94
#define PCPOKEMONLISTMENU         0x00
#define ITEMLISTMENU              0x03
#define W_WHICH_POKEMON           0xcf92
#define W_CUR_LIST_MENU_ITEM      0xcf91
#define W_CUR_ITEM                0xcf91
#define W_NAME_LIST_INDEX         0xd0b5
#define W_PREDEF_BANK             0xd0b7
#define W_MAX_ITEM_QUANTITY       0xcf97
#define W_MENU_EXIT_METHOD        0xd12e
#define W_CHOSEN_MENU_ITEM        0xd12d
#define W_MENU_CURSOR_LOCATION    0xcc30
#define W_PARTY_COUNT             0xd163
#define W_PARTY_MON_NICKS         0xd2b5
#define W_BOX_MON_NICKS           0xde06
#define W_NAME_BUFFER             0xcd6d
#define W_STRING_BUFFER           0xcf4b
#define W_TILE_MAP                0xc3a0
#define CHOSE_MENU_ITEM           1
#define CANCELLED_MENU            2
#define B_PAD_A                   0
#define B_PAD_B                   1
#define B_PAD_SELECT              2
#define B_PAD_DOWN                7
#define NAME_LENGTH               11
#define H_JOY_PRESSED             0xffb3
#define H_LOADED_ROM_BANK         0xffb8
#define R_ROMB                    0x2000
#define TX_END                    0x50
#define SCREEN_WIDTH              20

struct display_list_menu_id_state {
	port_u8 reserved;
};

/* Copy the TX_END-terminated name at `src` into `dst`. */
static void
copy_name(port_u8 *memory, port_u16 src, port_u16 dst)
{
	port_u8 c;
	port_u16 i = 0;

	do {
		c = memory[(port_u16)(src + i)];
		memory[(port_u16)(dst + i)] = c;
		i++;
	} while (c != TX_END && i < 32u);
}

/* GetPartyMonName([wWhichPokemon]): copy the party/box mon nickname. */
static void
get_party_mon_name(port_u8 *memory, port_u8 index)
{
	port_u16 base = (memory[W_LIST_POINTER] == memory[W_PARTY_COUNT])
		? (port_u16)W_PARTY_MON_NICKS
		: (port_u16)W_BOX_MON_NICKS;
	port_u16 src = (port_u16)((port_u16)base +
		(port_u16)index * NAME_LENGTH);

	copy_name(memory, src, W_STRING_BUFFER);
}

/* GetItemName([wCurItem]): ItemNames is a compressed ROM table, so full
 * decompression is deferred; record the item id and a terminator as a
 * best-effort placeholder (equivalence pending). */
static void
get_item_name(port_u8 *memory, port_u8 item)
{
	memory[W_STRING_BUFFER] = item;
	memory[W_STRING_BUFFER + 1] = TX_END;
}

static void
bankswitch_to(port_u8 *memory, port_u8 bank)
{
	memory[R_ROMB] = bank;
	memory[H_LOADED_ROM_BANK] = bank;
}

__attribute__((noinline, used)) void
port_display_list_menu_id(struct display_list_menu_id_state *state,
	port_u8 *memory)
{
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];
	port_u8 battle_type = memory[W_BATTLE_TYPE];
	port_u8 list_menu_id = memory[W_LIST_MENU_ID];
	port_u16 list_ptr;
	port_u8 list_count;
	port_u8 input;
	(void)state;

	/* --- DisplayListMenuID setup (home/list_menu.asm 4-56) --- */
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 0;
	memory[H_JOY7] = 1;
	if (battle_type != 0)
		bankswitch_to(memory, 0); /* BANK(DisplayBattleMenu) == home bank 0 */
	else
		bankswitch_to(memory, 1);

	memory[W_STATUS_FLAGS5] |= (1u << BIT_NO_TEXT_DELAY);
	memory[W_MENU_ITEM_TO_SWAP] = 0;
	memory[W_LIST_COUNT] = 0;

	list_ptr = (port_u16)(memory[W_LIST_POINTER] |
		((port_u16)memory[W_LIST_POINTER + 1] << 8));
	list_count = memory[list_ptr];
	memory[W_LIST_COUNT] = list_count;

	memory[W_TEXT_BOX_ID] = LIST_MENU_BOX; /* DisplayTextBoxID: display-only */
	memory[W_MENU_WATCH_MOVING_OOB] = 1;
	if (list_count < 2)
		memory[W_MAX_MENU_ITEM] = 1;
	else
		memory[W_MAX_MENU_ITEM] = 2;
	memory[W_TOP_MENU_ITEM_Y] = 4;
	memory[W_TOP_MENU_ITEM_X] = 5;
	memory[W_MENU_WATCHED_KEYS] =
		(1u << B_PAD_A) | (1u << B_PAD_B) | (1u << B_PAD_SELECT);
	/* DelayFrames(10): timing-only. */
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 1;

	/* --- DisplayListMenuIDLoop: one iteration (58-195) --- */
	if (battle_type != 0) {
		/* Old Man battle path: cursor placed at hlcoord 5,4 and A is
		 * treated as pressed; wCurrentMenuItem forced to 0. */
		port_u16 cursor =
			(port_u16)(W_TILE_MAP + 4 * SCREEN_WIDTH + 5);
		memory[W_CURRENT_MENU_ITEM] = 0;
		memory[W_MENU_CURSOR_LOCATION] = (port_u8)cursor;
		memory[W_MENU_CURSOR_LOCATION + 1] = (port_u8)(cursor >> 8);
		input = (port_u8)(1u << B_PAD_A);
	} else {
		/* HandleMenuInput: read the watched joypad state. */
		input = (port_u8)(memory[H_JOY_PRESSED] &
			memory[W_MENU_WATCHED_KEYS]);
	}

	if (input & (1u << B_PAD_A)) {
		/* .buttonAPressed */
		port_u8 current = memory[W_CURRENT_MENU_ITEM];
		port_u8 scroll = memory[W_LIST_SCROLL_OFFSET];
		port_u8 c = (port_u8)(current + scroll);

		memory[W_MENU_EXIT_METHOD] = 1; /* $01 */
		memory[W_CHOSEN_MENU_ITEM] = 1; /* $01 */
		memory[W_MENU_WATCH_MOVING_OOB] = 0;

		if (list_count == 0)
			goto exit_list_menu; /* Cancel */
		if ((port_u8)(list_count - 1) < c)
			goto exit_list_menu; /* Cancel (past last entry) */

		memory[W_WHICH_POKEMON] = c;
		if (list_menu_id == ITEMLISTMENU) {
			port_u16 hl;
			c = (port_u8)(c * 2); /* sla c */
			hl = (port_u16)((port_u16)(list_ptr + 1) + c);
			memory[W_CUR_LIST_MENU_ITEM] = memory[hl];
			memory[W_MAX_ITEM_QUANTITY] = memory[(port_u16)(hl + 1)];
			/* wCurItem shares the byte with wCurListMenuItem. */
			memory[W_NAME_LIST_INDEX] = memory[W_CUR_ITEM];
			memory[W_PREDEF_BANK] = 0; /* BANK(ItemNames) */
			get_item_name(memory, memory[W_CUR_ITEM]);
		} else {
			/* .pokemonList */
			get_party_mon_name(memory, c);
		}

		/* .storeChosenEntry */
		copy_name(memory, W_STRING_BUFFER, W_NAME_BUFFER);
		memory[W_MENU_EXIT_METHOD] = CHOSE_MENU_ITEM;
		memory[W_CHOSEN_MENU_ITEM] = current;
		memory[H_JOY7] = 0;
		memory[W_STATUS_FLAGS5] &=
			(port_u8)~(1u << BIT_NO_TEXT_DELAY);
		goto bankswitch_back;
	}

	if (input & (1u << B_PAD_B)) {
		/* .checkOtherKeys -> ExitListMenu */
		goto exit_list_menu;
	}

	if (input & (1u << B_PAD_SELECT)) {
		/* HandleItemListSwapping: deferred (equivalence pending). */
	} else if (input & (1u << B_PAD_DOWN)) {
		/* Scroll down: allowed only if list_count >= scroll+3. */
		port_u8 s = memory[W_LIST_SCROLL_OFFSET];
		port_u8 sum = (port_u8)(s + 3);
		if (list_count >= sum)
			memory[W_LIST_SCROLL_OFFSET] = (port_u8)(s + 1);
	} else {
		/* Up pressed: scroll up unless already at the top. */
		port_u8 s = memory[W_LIST_SCROLL_OFFSET];
		if (s != 0)
			memory[W_LIST_SCROLL_OFFSET] = (port_u8)(s - 1);
	}

bankswitch_back:
	memory[R_ROMB] = saved_bank;
	memory[H_LOADED_ROM_BANK] = saved_bank;
	return;

exit_list_menu:
	memory[W_MENU_EXIT_METHOD] = CANCELLED_MENU;
	goto bankswitch_back;
}
