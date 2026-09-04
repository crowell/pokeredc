#include "port_state.h"

#define W_STATUS_FLAGS4 0xd72eu
#define W_STATUS_FLAGS5 0xd730u
#define W_NPC_MOVEMENT_DIRECTIONS2 0xcc97u
#define W_NPC_MOVEMENT_DIRECTIONS2_INDEX 0xcd37u
#define W_SCRIPTED_NPC_WALK_COUNTER 0xcf18u
#define W_SPRITE_STATE_DATA1 0xc100u
#define H_CURRENT_SPRITE_OFFSET 0xffdau

void port_anim_scripted_npc_movement(struct cpu_register_state *, port_u8 *);
void port_get_sprite_screen_x_pointer(struct cpu_register_state *);
void port_get_sprite_screen_xy_pointer_common(struct cpu_register_state *, port_u8 *);
void port_get_sprite_screen_y_pointer(struct cpu_register_state *);
void port_init_scripted_npc_movement(struct cpu_register_state *, port_u8 *);

static void
bit7(struct cpu_register_state *registers, port_u8 value)
{
	registers->f = (registers->f & PORT_FLAG_C) | PORT_FLAG_H
		| ((value & 0x80u) == 0 ? PORT_FLAG_Z : 0);
}

static void
cp(struct cpu_register_state *registers, port_u8 value)
{
	port_u8 accumulator = registers->a;

	registers->f = PORT_FLAG_N | (accumulator == value ? PORT_FLAG_Z : 0)
		| ((accumulator & 15) < (value & 15) ? PORT_FLAG_H : 0)
		| (accumulator < value ? PORT_FLAG_C : 0);
}

static void
add(struct cpu_register_state *registers, port_u8 value)
{
	port_u8 accumulator = registers->a;
	port_u16 result = (port_u16)accumulator + value;

	registers->a = (port_u8)result;
	registers->f = (registers->a == 0 ? PORT_FLAG_Z : 0)
		| ((accumulator & 15) + (value & 15) > 15 ? PORT_FLAG_H : 0)
		| (result > 0xffu ? PORT_FLAG_C : 0);
}

static void
decrement_memory(struct cpu_register_state *registers, port_u8 *memory,
	port_u16 address)
{
	port_u8 previous = memory[address];

	memory[address]--;
	registers->f = (registers->f & PORT_FLAG_C) | PORT_FLAG_N
		| (memory[address] == 0 ? PORT_FLAG_Z : 0)
		| ((previous & 15) == 0 ? PORT_FLAG_H : 0);
}

static void
increment_memory(struct cpu_register_state *registers, port_u8 *memory,
	port_u16 address)
{
	port_u8 previous = memory[address];

	memory[address]++;
	registers->f = (registers->f & PORT_FLAG_C)
		| (memory[address] == 0 ? PORT_FLAG_Z : 0)
		| ((previous & 15) == 15 ? PORT_FLAG_H : 0);
}

/* Port of DoScriptedNPCMovement in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_do_scripted_npc_movement(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u8 offset = memory[H_CURRENT_SPRITE_OFFSET];
	port_u8 direction;
	port_u16 pointer;

	registers->a = memory[W_STATUS_FLAGS5];
	bit7(registers, registers->a);
	if (registers->f & PORT_FLAG_Z)
		return;

	registers->h = (port_u8)(W_STATUS_FLAGS4 >> 8);
	registers->l = (port_u8)W_STATUS_FLAGS4;
	bit7(registers, memory[W_STATUS_FLAGS4]);
	memory[W_STATUS_FLAGS4] |= 0x80u;
	if (registers->f & PORT_FLAG_Z) {
		port_init_scripted_npc_movement(registers, memory);
		return;
	}

	registers->h = (port_u8)(W_NPC_MOVEMENT_DIRECTIONS2 >> 8);
	registers->a = memory[W_NPC_MOVEMENT_DIRECTIONS2_INDEX];
	registers->l = (port_u8)W_NPC_MOVEMENT_DIRECTIONS2;
	add(registers, registers->l);
	registers->l = registers->a;
	if (registers->f & PORT_FLAG_C)
		registers->h++;
	pointer = ((port_u16)registers->h << 8) | registers->l;
	registers->a = memory[pointer];
	direction = registers->a;

	if (direction == 0x40u) {
		port_get_sprite_screen_y_pointer(registers);
		port_get_sprite_screen_xy_pointer_common(registers, memory);
		registers->c = 4;
		registers->a = 0xfe;
	} else if (direction == 0) {
		port_get_sprite_screen_y_pointer(registers);
		port_get_sprite_screen_xy_pointer_common(registers, memory);
		registers->c = 0;
		registers->a = 2;
	} else if (direction == 0x80u) {
		port_get_sprite_screen_x_pointer(registers);
		port_get_sprite_screen_xy_pointer_common(registers, memory);
		registers->c = 8;
		registers->a = 0xfe;
	} else if (direction == 0xc0u) {
		port_get_sprite_screen_x_pointer(registers);
		port_get_sprite_screen_xy_pointer_common(registers, memory);
		registers->c = 12;
		registers->a = 2;
	} else {
		cp(registers, 0xffu);
		return;
	}

	registers->b = registers->a;
	pointer = ((port_u16)registers->h << 8) | registers->l;
	registers->a = memory[pointer];
	add(registers, registers->b);
	memory[pointer] = registers->a;
	registers->a = offset;
	add(registers, 9);
	registers->l = registers->a;
	registers->a = registers->c;
	memory[W_SPRITE_STATE_DATA1 | registers->l] = registers->a;
	port_anim_scripted_npc_movement(registers, memory);

	registers->h = (port_u8)(W_SCRIPTED_NPC_WALK_COUNTER >> 8);
	registers->l = (port_u8)W_SCRIPTED_NPC_WALK_COUNTER;
	decrement_memory(registers, memory, W_SCRIPTED_NPC_WALK_COUNTER);
	if (!(registers->f & PORT_FLAG_Z))
		return;

	registers->a = 8;
	memory[W_SCRIPTED_NPC_WALK_COUNTER] = registers->a;
	registers->h = (port_u8)(W_NPC_MOVEMENT_DIRECTIONS2_INDEX >> 8);
	registers->l = (port_u8)W_NPC_MOVEMENT_DIRECTIONS2_INDEX;
	increment_memory(registers, memory, W_NPC_MOVEMENT_DIRECTIONS2_INDEX);
}
