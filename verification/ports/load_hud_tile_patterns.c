#include "port_state.h"

void port_far_copy_data_double(struct far_copy_double_state *, port_u8 *);
void port_copy_video_data_double(struct cpu_register_state *, port_u8 *);

static void
load_hud_add_a(struct cpu_register_state *registers)
{
	port_u8 old = registers->a;
	port_u16 wide = (port_u16)old + old;

	registers->a = (port_u8)wide;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) + (old & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xff)
		registers->f |= PORT_FLAG_C;
}

static void
load_hud_set_far_transfer(struct cpu_register_state *registers,
	port_u16 source, port_u16 destination, port_u16 bank_count)
{
	registers->h = (port_u8)(source >> 8);
	registers->l = (port_u8)source;
	registers->d = (port_u8)(destination >> 8);
	registers->e = (port_u8)destination;
	registers->b = (port_u8)(bank_count >> 8);
	registers->c = (port_u8)bank_count;
}

static void
load_hud_set_video_transfer(struct cpu_register_state *registers,
	port_u16 source, port_u16 destination, port_u16 bank_count)
{
	registers->d = (port_u8)(source >> 8);
	registers->e = (port_u8)source;
	registers->h = (port_u8)(destination >> 8);
	registers->l = (port_u8)destination;
	registers->b = (port_u8)(bank_count >> 8);
	registers->c = (port_u8)bank_count;
}

/* Port of LoadHudTilePatterns in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_load_hud_tile_patterns(struct load_hud_tile_patterns_state *state,
	port_u8 *memory)
{
	struct cpu_register_state *registers = &state->transfer.registers;

	registers->a = state->lcd_control;
	load_hud_add_a(registers);
	if ((registers->f & PORT_FLAG_C) != 0) {
		load_hud_set_video_transfer(registers, 0x6080, 0x96d0,
			0x0403);
		port_copy_video_data_double(registers, memory);
		load_hud_set_video_transfer(registers, 0x6098, 0x9730,
			0x0406);
		port_copy_video_data_double(registers, memory);
		return;
	}

	load_hud_set_far_transfer(registers, 0x6080, 0x96d0, 0x0018);
	registers->a = 0x04;
	port_far_copy_data_double(&state->transfer, memory);
	load_hud_set_far_transfer(registers, 0x6098, 0x9730, 0x0030);
	registers->a = 0x04;
	port_far_copy_data_double(&state->transfer, memory);
}
