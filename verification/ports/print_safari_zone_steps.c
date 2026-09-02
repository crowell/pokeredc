#include "port_state.h"

#define W_CUR_MAP 0xd35eu
#define W_SAFARI_STEPS 0xd70du
#define W_NUM_SAFARI_BALLS 0xda47u
#define W_TILE_MAP 0xc3a0u
#define SAFARI_ZONE_EAST 0xd9u
#define CERULEAN_CAVE_2F 0xe2u
#define SAFARI_STEPS_TEXT 0x4579u
#define SAFARI_BALL_TEXT 0x457eu

void port_text_box_border(struct text_box_border_state *, port_u8 *);
void port_print_number(struct print_number_state *);
void port_place_string(struct cpu_register_state *, port_u8 *);

static void
set_hl(struct cpu_register_state *registers, port_u16 value)
{
	registers->h = (port_u8)(value >> 8);
	registers->l = (port_u8)value;
}

static void
set_de(struct cpu_register_state *registers, port_u16 value)
{
	registers->d = (port_u8)(value >> 8);
	registers->e = (port_u8)value;
}

static void
cp_a(struct cpu_register_state *registers, port_u8 value)
{
	port_u8 left = registers->a;

	registers->f = PORT_FLAG_N;
	if (left == value)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (value & 0x0fu))
		registers->f |= PORT_FLAG_H;
	if (left < value)
		registers->f |= PORT_FLAG_C;
}

static void
print_number(struct cpu_register_state *registers, port_u8 *memory,
	port_u16 destination, port_u16 source, port_u8 bytes, port_u8 digits)
{
	struct print_number_state number = {0};

	number.registers = *registers;
	set_hl(&number.registers, destination);
	set_de(&number.registers, source);
	number.registers.b = bytes;
	number.registers.c = digits;
	for (port_u8 index = 0; index < 3u; ++index)
		number.source[index] = memory[(port_u16)(source + index)];
	port_print_number(&number);
	for (port_u8 index = 0; index < number.write_count; ++index) {
		port_u16 address = (port_u16)(((port_u16)number.write_trace_h[index] << 8) |
			number.write_trace_l[index]);
		memory[address] = number.write_trace_values[index];
	}
	*registers = number.registers;
}

static void
place_string(struct cpu_register_state *registers, port_u8 *memory,
	port_u16 destination, port_u16 source)
{
	set_hl(registers, destination);
	set_de(registers, source);
	port_place_string(registers, memory);
}

/* Port of PrintSafariZoneSteps in engine/overworld/player_state.asm. */
__attribute__((noinline, used)) void
port_print_safari_zone_steps(struct cpu_register_state *registers,
	port_u8 *memory)
{
	struct text_box_border_state border = {0};

	registers->a = memory[W_CUR_MAP];
	cp_a(registers, SAFARI_ZONE_EAST);
	if ((registers->f & PORT_FLAG_C) != 0)
		return;
	cp_a(registers, CERULEAN_CAVE_2F);
	if ((registers->f & PORT_FLAG_C) == 0)
		return;

	set_hl(registers, W_TILE_MAP);
	registers->b = 3;
	registers->c = 7;
	border.registers = *registers;
	port_text_box_border(&border, memory);
	*registers = border.registers;

	print_number(registers, memory, W_TILE_MAP + 21u, W_SAFARI_STEPS, 2, 3);
	place_string(registers, memory, W_TILE_MAP + 24u, SAFARI_STEPS_TEXT);
	place_string(registers, memory, W_TILE_MAP + 61u, SAFARI_BALL_TEXT);

	registers->a = memory[W_NUM_SAFARI_BALLS];
	cp_a(registers, 10);
	if ((registers->f & PORT_FLAG_C) != 0) {
		set_hl(registers, W_TILE_MAP + 65u);
		registers->a = 0x7fu;
		memory[W_TILE_MAP + 65u] = registers->a;
	}
	print_number(registers, memory, W_TILE_MAP + 66u, W_NUM_SAFARI_BALLS, 1, 2);
}
