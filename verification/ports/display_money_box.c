#include "port_state.h"

#define W_STATUS_FLAGS5 0xd730u
#define W_TEXT_BOX_ID 0xd125u
#define W_PLAYER_MONEY 0xd347u
#define SCREEN_TILEMAP 0xc3a0u
#define SCREEN_WIDTH 20u
#define MONEY_BOX_TEMPLATE 0x0fu
#define BIT_NO_TEXT_DELAY 6u
#define LEADING_ZEROES 0x80u
#define MONEY_SIGN 0x20u

void port_display_text_box_id(struct cpu_register_state *, port_u8 *);
void port_clear_screen_area(struct clear_screen_area_state *, port_u8 *);
void port_print_bcd_number(struct cpu_register_state *, port_u8 *);

static port_u16
screen_coord(port_u8 row, port_u8 column)
{
	return (port_u16)(SCREEN_TILEMAP + (port_u16)row * SCREEN_WIDTH + column);
}

/* Port of the DisplayMoneyBox handler in engine/menus/text_box.asm. */
__attribute__((noinline, used)) void
port_display_money_box(struct cpu_register_state *registers, port_u8 *memory)
{
	struct clear_screen_area_state clear;

	memory[W_STATUS_FLAGS5] |= (port_u8)(1u << BIT_NO_TEXT_DELAY);
	registers->a = MONEY_BOX_TEMPLATE;
	memory[W_TEXT_BOX_ID] = MONEY_BOX_TEMPLATE;
	port_display_text_box_id(registers, memory);

	clear.registers = *registers;
	clear.registers.h = (port_u8)(screen_coord(1, 13) >> 8);
	clear.registers.l = (port_u8)screen_coord(1, 13);
	clear.registers.b = 1;
	clear.registers.c = 6;
	port_clear_screen_area(&clear, memory);
	*registers = clear.registers;

	registers->h = (port_u8)(screen_coord(1, 12) >> 8);
	registers->l = (port_u8)screen_coord(1, 12);
	registers->d = (port_u8)(W_PLAYER_MONEY >> 8);
	registers->e = (port_u8)W_PLAYER_MONEY;
	registers->c = (port_u8)(3u | LEADING_ZEROES | MONEY_SIGN);
	port_print_bcd_number(registers, memory);

	registers->h = (port_u8)(W_STATUS_FLAGS5 >> 8);
	registers->l = (port_u8)W_STATUS_FLAGS5;
	memory[W_STATUS_FLAGS5] &= (port_u8)~(1u << BIT_NO_TEXT_DELAY);
}
