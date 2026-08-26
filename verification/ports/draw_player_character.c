#include "port_state.h"

void port_far_copy_data2(struct far_copy_data2_state *, port_u8 *);
void port_clear_sprites(struct clear_sprites_state *);

static void
draw_player_add(struct cpu_register_state *registers, port_u8 value)
{
	port_u8 left = registers->a;
	port_u16 result = (port_u16)left + value;

	registers->a = (port_u8)result;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (value & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (result > 0xff)
		registers->f |= PORT_FLAG_C;
}

static void
draw_player_inc_a(struct cpu_register_state *registers)
{
	port_u8 old = registers->a;

	registers->a++;
	registers->f &= PORT_FLAG_C;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0x0f)
		registers->f |= PORT_FLAG_H;
}

static void
draw_player_dec(struct cpu_register_state *registers, port_u8 *value)
{
	port_u8 old = *value;

	(*value)--;
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_N;
	if (*value == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

/* Port of DrawPlayerCharacter in engine/movie/title.asm. */
__attribute__((noinline, used)) void
port_draw_player_character(struct draw_player_character_state *state,
	port_u8 *memory)
{
	struct cpu_register_state *registers = &state->sprites.registers;
	struct far_copy_data2_state copy;
	port_u8 row;
	port_u8 column;
	port_u8 oam_index = 0;

	copy.registers = *registers;
	copy.requested_bank = state->requested_bank;
	copy.loaded_bank = state->loaded_bank;
	copy.rom_bank = state->rom_bank;
	copy.registers.h = 0x66;
	copy.registers.l = 0xa8;
	copy.registers.d = 0x80;
	copy.registers.e = 0;
	copy.registers.b = 0x02;
	copy.registers.c = 0x30;
	copy.registers.a = 0x04;
	port_far_copy_data2(&copy, memory);
	*registers = copy.registers;
	state->requested_bank = copy.requested_bank;
	state->loaded_bank = copy.loaded_bank;
	state->rom_bank = copy.rom_bank;

	port_clear_sprites(&state->sprites);

	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	state->player_character_oam_tile = registers->a;
	registers->h = 0xc3;
	registers->l = 0;
	registers->d = 0x60;
	registers->e = 0x5a;
	registers->b = 7;
	for (row = 0; row < 7; row++) {
		port_u8 saved_d = registers->d;
		port_u8 saved_e = registers->e;

		registers->c = 5;
		for (column = 0; column < 5; column++) {
			registers->a = registers->d;
			state->sprites.oam[oam_index++] = registers->a;
			registers->l++;
			registers->a = registers->e;
			state->sprites.oam[oam_index++] = registers->a;
			registers->l++;
			draw_player_add(registers, 8);
			registers->e = registers->a;
			registers->a = state->player_character_oam_tile;
			state->sprites.oam[oam_index++] = registers->a;
			registers->l++;
			draw_player_inc_a(registers);
			state->player_character_oam_tile = registers->a;
			oam_index++;
			registers->l++;
			draw_player_dec(registers, &registers->c);
		}
		registers->d = saved_d;
		registers->e = saved_e;
		registers->a = 8;
		draw_player_add(registers, registers->d);
		registers->d = registers->a;
		draw_player_dec(registers, &registers->b);
	}
}
