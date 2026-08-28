#include "port_state.h"

#define W_FIELD_MOVES 0xcd3du
#define W_NUM_FIELD_MOVES 0xcd41u
#define W_FIELD_MOVES_LEFTMOST_XCOORD 0xcd42u
#define W_WHICH_POKEMON 0xcf92u
#define W_PARTY_MON1_MOVES 0xd173u
#define W_UPDATE_SPRITES_ENABLED 0xcfcbu
#define H_FIELD_MOVE_MON_MENU_TOP_MENU_ITEM_X 0xfff7u
#define SCREEN_TILEMAP 0xc3a0u
#define SCREEN_WIDTH 20u
#define W_POKEMON_MENU_ENTRIES 0x77c2u
#define FIELD_MOVE_NAMES 0x778du
#define PARTYMON_STRUCT_LENGTH 0x2cu

void port_get_mon_field_moves(struct cpu_register_state *, port_u8 *);
void port_text_box_border(struct text_box_border_state *, port_u8 *);
void port_update_sprites(struct cpu_register_state *, port_u8 *);
void port_place_string(struct cpu_register_state *, port_u8 *);

static port_u16
coord(port_u8 row, port_u8 column)
{
	return (port_u16)(SCREEN_TILEMAP + (port_u16)row * SCREEN_WIDTH + column);
}

static void
set_hl(struct cpu_register_state *r, port_u16 value)
{
	r->h = (port_u8)(value >> 8);
	r->l = (port_u8)value;
}

static port_u16
get_hl(const struct cpu_register_state *r)
{
	return (port_u16)(((port_u16)r->h << 8) | r->l);
}

static void
add_hl(struct cpu_register_state *r, port_u16 value)
{
	port_u16 left = get_hl(r);
	port_u32 wide = (port_u32)left + value;
	port_u8 flags = (port_u8)(r->f & PORT_FLAG_Z);
	if ((left & 0x0fffu) + (value & 0x0fffu) > 0x0fffu)
		flags |= PORT_FLAG_H;
	if (wide > 0xffffu)
		flags |= PORT_FLAG_C;
	set_hl(r, (port_u16)wide);
	r->f = flags;
}

static void
border(struct cpu_register_state *r, port_u8 *memory, port_u8 row,
	port_u8 column, port_u8 height, port_u8 width)
{
	struct text_box_border_state state;
	state.registers = *r;
	set_hl(&state.registers, coord(row, column));
	state.registers.b = height;
	state.registers.c = width;
	port_text_box_border(&state, memory);
	*r = state.registers;
}

static void
border_at(struct cpu_register_state *r, port_u8 *memory)
{
	struct text_box_border_state state;
	state.registers = *r;
	port_text_box_border(&state, memory);
	*r = state.registers;
}

static void
update(struct cpu_register_state *r, port_u8 *memory)
{
	port_update_sprites(r, memory);
}

/* Port of DisplayFieldMoveMonMenu in engine/menus/text_box.asm. */
__attribute__((noinline, used)) void
port_display_field_move_mon_menu(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u8 count;
	port_u8 leftmost;
	port_u16 destination;
	port_u16 field_ptr;

	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	set_hl(registers, W_FIELD_MOVES);
	for (port_u8 i = 0; i < 4; ++i) {
		memory[(port_u16)(get_hl(registers))] = 0;
		set_hl(registers, (port_u16)(get_hl(registers) + 1));
	}
	memory[W_NUM_FIELD_MOVES] = 0;
	set_hl(registers, (port_u16)(get_hl(registers) + 1));
	memory[W_FIELD_MOVES_LEFTMOST_XCOORD] = 12;
	port_get_mon_field_moves(registers, memory);

	count = memory[W_NUM_FIELD_MOVES];
	registers->a = count;
	registers->f = (count == 0) ? PORT_FLAG_Z : 0;
	if (count == 0) {
		border(registers, memory, 11, 11, 5, 7);
		update(registers, memory);
		registers->a = 12;
		memory[H_FIELD_MOVE_MON_MENU_TOP_MENU_ITEM_X] = 12;
		set_hl(registers, coord(12, 13));
		registers->d = (port_u8)(W_POKEMON_MENU_ENTRIES >> 8);
		registers->e = (port_u8)W_POKEMON_MENU_ENTRIES;
		port_place_string(registers, memory);
		return;
	}

	leftmost = memory[W_FIELD_MOVES_LEFTMOST_XCOORD];
	set_hl(registers, coord(11, 0));
	registers->a = (port_u8)(leftmost - 1);
	registers->e = registers->a;
	registers->d = 0;
	add_hl(registers, registers->e);
	registers->b = 5;
	registers->a = (port_u8)(18 - registers->e);
	registers->c = registers->a;
	registers->a = count;
	registers->d = 0xff;
	registers->e = (port_u8)(-SCREEN_WIDTH * 2);
	while (registers->a != 0) {
		add_hl(registers, (port_u16)0xffd8);
		registers->b = (port_u8)(registers->b + 2);
		registers->a--;
		registers->f = (registers->a == 0) ? PORT_FLAG_Z : 0;
	}
	add_hl(registers, (port_u16)0xffec);
	registers->b++;
	border_at(registers, memory);
	update(registers, memory);

	set_hl(registers, coord(12, 0));
	leftmost = memory[W_FIELD_MOVES_LEFTMOST_XCOORD];
	registers->a = (port_u8)(leftmost + 1);
	registers->e = registers->a;
	registers->d = 0;
	add_hl(registers, registers->e);
	registers->d = 0xff;
	registers->e = (port_u8)(-SCREEN_WIDTH * 2);
	registers->a = memory[W_NUM_FIELD_MOVES];
	while (registers->a != 0) {
		add_hl(registers, (port_u16)0xffd8);
		registers->a--;
		registers->f = (registers->a == 0) ? PORT_FLAG_Z : 0;
	}

	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	memory[W_NUM_FIELD_MOVES] = 0;
	destination = get_hl(registers);
	registers->d = (port_u8)(W_FIELD_MOVES >> 8);
	registers->e = (port_u8)W_FIELD_MOVES;
	field_ptr = W_FIELD_MOVES;
	for (;;) {
		port_u16 saved_destination = destination;
		port_u16 source = field_ptr;
		port_u8 name_index = memory[source];
		if (name_index == 0)
			break;
		source = FIELD_MOVE_NAMES;
		port_u8 index = name_index;
		while (--index != 0) {
			do {
				source++;
			} while (memory[source - 1] != 0x50);
		}
		registers->h = (port_u8)(saved_destination >> 8);
		registers->l = (port_u8)saved_destination;
		registers->d = (port_u8)(source >> 8);
		registers->e = (port_u8)source;
		port_place_string(registers, memory);
		destination = (port_u16)(get_hl(registers) + SCREEN_WIDTH * 2);
		registers->h = (port_u8)(destination >> 8);
		registers->l = (port_u8)destination;
		field_ptr++;
		registers->d = (port_u8)(field_ptr >> 8);
		registers->e = (port_u8)field_ptr;
	}

	registers->a = leftmost;
	memory[H_FIELD_MOVE_MON_MENU_TOP_MENU_ITEM_X] = leftmost;
	set_hl(registers, coord(12, (port_u8)(leftmost + 1)));
	registers->d = (port_u8)(W_POKEMON_MENU_ENTRIES >> 8);
	registers->e = (port_u8)W_POKEMON_MENU_ENTRIES;
	port_place_string(registers, memory);
}
