#include "port_state.h"

#define W_TILE_MAP 0xc3a0u
#define W_PLAYER_NAME 0xd158u
#define W_NUM_SET_BITS 0xd11eu
#define H_AUTO_BG_TRANSFER_ENABLED 0xffbau
#define SAVE_SCREEN_INFO_TEXT 0x5e6au

void port_text_box_border(struct text_box_border_state *, port_u8 *);
void port_place_string(struct cpu_register_state *, port_u8 *);
void port_print_num_badges(struct print_number_state *, port_u8 *);
void port_print_num_owned_mons(struct print_number_state *, port_u8 *);
void port_print_play_time(struct print_number_state *, port_u8 *);
void port_delay_frames(struct delay_frame_state *, const port_u8 *);

static void
display_place_string(struct cpu_register_state *registers, port_u8 *memory,
	port_u16 destination, port_u16 source)
{
	registers->h = (port_u8)(destination >> 8);
	registers->l = (port_u8)destination;
	registers->d = (port_u8)(source >> 8);
	registers->e = (port_u8)source;
	port_place_string(registers, memory);
}

/* Port of DisplayContinueGameInfo in engine/menus/main_menu.asm. */
__attribute__((noinline, used)) void
port_display_continue_game_info(struct cpu_register_state *registers,
	port_u8 *memory, const port_u8 *observations)
{
	struct text_box_border_state border;
	struct print_number_state number;
	struct delay_frame_state delay;

	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 0;
	border.registers = *registers;
	border.registers.h = 0xc4;
	border.registers.l = 0x30;
	border.registers.b = 8;
	border.registers.c = 14;
	port_text_box_border(&border, memory);
	*registers = border.registers;

	display_place_string(registers, memory, 0xc459, SAVE_SCREEN_INFO_TEXT);
	display_place_string(registers, memory, 0xc460, W_PLAYER_NAME);

	number.registers = *registers;
	number.registers.h = 0xc4;
	number.registers.l = 0x8d;
	port_print_num_badges(&number, memory);
	*registers = number.registers;

	number.registers = *registers;
	number.registers.h = 0xc4;
	number.registers.l = 0xb4;
	port_print_num_owned_mons(&number, memory);
	*registers = number.registers;

	number.registers = *registers;
	number.registers.h = 0xc4;
	number.registers.l = 0xd9;
	port_print_play_time(&number, memory);
	*registers = number.registers;

	registers->a = 1;
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 1;
	delay.registers = *registers;
	delay.registers.c = 30;
	port_delay_frames(&delay, observations);
	*registers = delay.registers;
}
