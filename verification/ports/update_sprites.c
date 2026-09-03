#include "port_state.h"

#define W_UPDATE_SPRITES_ENABLED 0xcfcbu
#define W_NPC_MOVEMENT_SCRIPT_SPRITE_OFFSET 0xcf14u
#define W_SPRITE_STATE_DATA2 0xc200u
#define H_LOADED_ROM_BANK 0xffb8u
#define H_CURRENT_SPRITE_OFFSET 0xffdau
#define H_TILE_PLAYER_STANDING_ON 0xff93u
#define R_ROMB 0x2000u

void port_do_scripted_npc_movement(struct cpu_register_state *, port_u8 *);
void port_update_npc_sprite(struct cpu_register_state *, port_u8 *);
void port_update_player_sprite(struct cpu_register_state *, port_u8 *);

static void
sub_a(struct cpu_register_state *registers, port_u8 value)
{
	port_u8 previous = registers->a;

	registers->a -= value;
	registers->f = PORT_FLAG_N | (registers->a == 0 ? PORT_FLAG_Z : 0)
		| ((previous & 0x0fu) < (value & 0x0fu) ? PORT_FLAG_H : 0)
		| (previous < value ? PORT_FLAG_C : 0);
}

static void
add_a(struct cpu_register_state *registers, port_u8 value)
{
	port_u8 previous = registers->a;
	port_u16 result = (port_u16)previous + value;

	registers->a = (port_u8)result;
	registers->f = (registers->a == 0 ? PORT_FLAG_Z : 0)
		| ((previous & 0x0fu) + (value & 0x0fu) > 0x0fu
			? PORT_FLAG_H : 0)
		| (result > 0xffu ? PORT_FLAG_C : 0);
}

static void
and_a(struct cpu_register_state *registers)
{
	registers->f = PORT_FLAG_H | (registers->a == 0 ? PORT_FLAG_Z : 0);
}

static void
cp_a(struct cpu_register_state *registers, port_u8 value)
{
	port_u8 previous = registers->a;

	registers->f = PORT_FLAG_N | (previous == value ? PORT_FLAG_Z : 0)
		| ((previous & 0x0fu) < (value & 0x0fu) ? PORT_FLAG_H : 0)
		| (previous < value ? PORT_FLAG_C : 0);
}

static void
dec_a(struct cpu_register_state *registers)
{
	port_u8 previous = registers->a;

	registers->a--;
	registers->f = (registers->f & PORT_FLAG_C) | PORT_FLAG_N
		| (registers->a == 0 ? PORT_FLAG_Z : 0)
		| ((previous & 0x0fu) == 0 ? PORT_FLAG_H : 0);
}

static void
swap_a(struct cpu_register_state *registers)
{
	registers->a = (port_u8)((registers->a << 4) | (registers->a >> 4));
	registers->f = registers->a == 0 ? PORT_FLAG_Z : 0;
}

static void
update_current_sprite(struct cpu_register_state *registers, port_u8 *memory)
{
	cp_a(registers, 1);
	if (registers->f & PORT_FLAG_Z) {
		port_update_player_sprite(registers, memory);
		return;
	}

	dec_a(registers);
	swap_a(registers);
	memory[H_TILE_PLAYER_STANDING_ON] = registers->a;
	registers->a = memory[W_NPC_MOVEMENT_SCRIPT_SPRITE_OFFSET];
	registers->b = registers->a;
	registers->a = memory[H_CURRENT_SPRITE_OFFSET];
	cp_a(registers, registers->b);
	if (registers->f & PORT_FLAG_Z) {
		port_do_scripted_npc_movement(registers, memory);
		return;
	}

	port_update_npc_sprite(registers, memory);
}

/* Port of _UpdateSprites in engine/overworld/sprite_collisions.asm. */
__attribute__((noinline, used)) void
port_update_sprites_private(struct cpu_register_state *registers,
	port_u8 *memory)
{
	registers->h = (port_u8)(W_SPRITE_STATE_DATA2 >> 8);
	registers->a = 14;
	do {
		port_u8 saved_b;
		port_u8 saved_c;
		port_u8 saved_d;
		port_u8 saved_e;
		port_u8 saved_h;
		port_u8 saved_l;

		registers->l = registers->a;
		sub_a(registers, 14);
		registers->c = registers->a;
		memory[H_CURRENT_SPRITE_OFFSET] = registers->a;
		registers->a = memory[((port_u16)registers->h << 8) | registers->l];
		and_a(registers);
		if (registers->a != 0) {
			saved_b = registers->b;
			saved_c = registers->c;
			saved_d = registers->d;
			saved_e = registers->e;
			saved_h = registers->h;
			saved_l = registers->l;
			update_current_sprite(registers, memory);
			registers->b = saved_b;
			registers->c = saved_c;
			registers->d = saved_d;
			registers->e = saved_e;
			registers->h = saved_h;
			registers->l = saved_l;
		}
		registers->a = registers->l;
		add_a(registers, 16);
		cp_a(registers, 14);
	} while (!(registers->f & PORT_FLAG_Z));
}

/* Port of UpdateSprites in home/update_sprites.asm. */
__attribute__((noinline, used)) void
port_update_sprites(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u8 before = memory[W_UPDATE_SPRITES_ENABLED];
	port_u8 value = (port_u8)(before - 1);
	port_u8 saved_a;
	port_u8 saved_f;
	port_u8 saved_bank;

	registers->a = value;
	registers->f = (port_u8)(registers->f & PORT_FLAG_C);
	registers->f |= PORT_FLAG_N;
	if (value == 0)
		registers->f |= PORT_FLAG_Z;
	if ((before & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
	if (value != 0)
		return;

	saved_a = memory[H_LOADED_ROM_BANK];
	saved_f = registers->f;
	saved_bank = memory[H_LOADED_ROM_BANK];
	registers->a = 1;
	memory[H_LOADED_ROM_BANK] = 1;
	memory[R_ROMB] = 1;
	port_update_sprites_private(registers, memory);
	registers->a = saved_a;
	registers->f = saved_f;
	memory[H_LOADED_ROM_BANK] = saved_bank;
	memory[R_ROMB] = saved_a;
}
