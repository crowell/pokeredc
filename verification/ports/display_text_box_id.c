#include "port_state.h"

/* Port of DisplayTextBoxID_ in engine/menus/text_box.asm.
 *
 * The money-box and two-option function-table entries compose through their
 * real ports; the remaining interactive menu entries remain explicit
 * boundaries.  The coordinate-only and text-and-coordinate entries execute
 * their real table lookup, coordinate arithmetic, border drawing, text
 * placement, and sprite-update callees here.
 */

#define W_TEXT_BOX_ID 0xd125u
#define W_STATUS_FLAGS5 0xd730u
#define H_UI_LAYOUT_FLAGS 0xfff6u
#define MONEY_BOX 0x13u
#define TWO_OPTION_MENU 0x14u
#define PORT_FLAG_C 0x10u
#define TEXT_BOX_FUNCTION_TABLE 0x7387u
#define TEXT_BOX_COORD_TABLE 0x7391u
#define TEXT_BOX_TEXT_AND_COORD_TABLE 0x73b0u
#define BIT_NO_TEXT_DELAY 6

void port_text_box_border(struct text_box_border_state *, port_u8 *);
void port_place_string(struct cpu_register_state *, port_u8 *);
void port_update_sprites(struct cpu_register_state *, port_u8 *);
port_u8 port_search_text_box_table(struct text_box_search_state *,
	const port_u8 *);
void port_get_text_box_id_coords(struct text_box_coords_state *);
void port_get_text_box_id_text(struct cpu_register_state *, port_u8 *);
void port_get_address_of_screen_coords(struct screen_coords_state *);
void port_display_two_option_menu(struct cpu_register_state *, port_u8 *);
void port_display_money_box(struct cpu_register_state *, port_u8 *);

static port_u16
pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
set_pair(port_u8 *high, port_u8 *low, port_u16 value)
{
	*high = (port_u8)(value >> 8);
	*low = (port_u8)value;
}

static port_u8
search(struct cpu_register_state *registers, port_u8 *memory,
	port_u16 table, port_u16 stride)
{
	struct text_box_search_state state;
	port_u8 result;
	state.registers = *registers;
	set_pair(&state.registers.h, &state.registers.l, table);
	set_pair(&state.registers.d, &state.registers.e, stride);
	result = port_search_text_box_table(&state, memory);
	*registers = state.registers;
	return result;
}

static void
load_coords(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u16 table = pair(registers->h, registers->l);
	struct text_box_coords_state state;
	state.registers = *registers;
	for (port_u8 i = 0; i < 4; ++i)
		state.fetched[i] = memory[(port_u16)(table + i)];
	port_get_text_box_id_coords(&state);
	*registers = state.registers;
}

static void
draw_box(struct cpu_register_state *registers, port_u8 *memory)
{
	struct screen_coords_state coords;
	coords.registers = *registers;
	port_get_address_of_screen_coords(&coords);
	*registers = coords.registers;

	{
		struct text_box_border_state border;
		border.registers = *registers;
		port_text_box_border(&border, memory);
		*registers = border.registers;
	}
}

static __attribute__((noinline)) void
port_display_text_box_id_impl(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u8 id = memory[W_TEXT_BOX_ID];
	port_u8 result;

	registers->a = id;
	if (id == TWO_OPTION_MENU) {
		port_display_two_option_menu(registers, memory);
		return;
	}
	if (id == MONEY_BOX) {
		/* SearchTextBoxTable reports the function-table hit with carry set. */
		registers->f = PORT_FLAG_C;
		port_display_money_box(registers, memory);
		return;
	}
	registers->c = id;

	result = search(registers, memory, TEXT_BOX_FUNCTION_TABLE, 3);
	if (result == 1)
		return; /* function-table handlers own their complete interaction */

	result = search(registers, memory, TEXT_BOX_COORD_TABLE, 5);
	if (result == 1) {
		load_coords(registers, memory);
		draw_box(registers, memory);
		return;
	}

	result = search(registers, memory, TEXT_BOX_TEXT_AND_COORD_TABLE, 9);
	if (result != 1)
		return;

	load_coords(registers, memory);
	{
		port_u16 text_table = pair(registers->h, registers->l);
		draw_box(registers, memory);
		set_pair(&registers->h, &registers->l, text_table);
		port_get_text_box_id_text(registers, memory);
	}

	{
		port_u8 old_flags = memory[W_STATUS_FLAGS5];
		memory[W_STATUS_FLAGS5] =
			(port_u8)(old_flags | (1u << BIT_NO_TEXT_DELAY));
		port_place_string(registers, memory);
		memory[W_STATUS_FLAGS5] = old_flags;
	}
	port_update_sprites(registers, memory);
}

__attribute__((noinline, used)) void
port_display_text_box_id(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_display_text_box_id_impl(registers, memory);
}

/* Test-only entry that keeps the nested DisplayTextBoxID call at its
 * independently proven boundary while exercising the outer dispatcher. */
__attribute__((noinline, used)) void
port_display_text_box_id_money_dispatch(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_display_text_box_id_impl(registers, memory);
}
