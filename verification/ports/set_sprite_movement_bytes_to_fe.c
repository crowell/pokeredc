#include "port_state.h"

void port_get_sprite_movement_byte1_pointer(
	struct memory_predicate_state *state);
void port_get_sprite_movement_byte2_pointer(
	struct memory_predicate_state *state);

#define H_SPRITE_INDEX 0xff8cu
#define H_SPRITE_MOVEMENT_BYTE2 0xff8du

__attribute__((noinline, used)) void
port_set_sprite_movement_bytes_to_fe(
	struct cpu_register_state *state, port_u8 *memory)
{
	struct memory_predicate_state pointer;
	port_u8 saved_h = state->h;
	port_u8 saved_l = state->l;
	port_u16 address;

	pointer.registers = *state;
	pointer.value = memory[H_SPRITE_INDEX];
	port_get_sprite_movement_byte1_pointer(&pointer);
	*state = pointer.registers;
	address = (port_u16)(((port_u16)state->h << 8) | state->l);
	memory[address] = 0xfe;

	pointer.registers = *state;
	pointer.value = memory[H_SPRITE_INDEX];
	port_get_sprite_movement_byte2_pointer(&pointer);
	*state = pointer.registers;
	state->a = memory[H_SPRITE_MOVEMENT_BYTE2];
	address = (port_u16)(((port_u16)state->h << 8) | state->l);
	memory[address] = state->a;

	state->h = saved_h;
	state->l = saved_l;
}
