#include "port_state.h"

static void
add_immediate(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	port_u8 result = (port_u8)(left + right);
	registers->f = 0;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if ((unsigned)left + right > 0xff)
		registers->f |= PORT_FLAG_C;
	registers->a = result;
}

__attribute__((noinline, used)) void
port_update_sprite_movement_delay_begin(
	struct sprite_movement_delay_state *state)
{
	port_u8 old_delay;
	port_u8 ready;
	state->registers.h = 0xc2;
	state->registers.a = state->current_offset;
	add_immediate(&state->registers, 6);
	state->registers.l = state->registers.a;
	state->registers.a = state->movement_byte;
	state->registers.l++;
	state->registers.l++;
	ready = state->movement_byte < 0xfe;
	if (ready) {
		state->movement_delay = 0;
	} else {
		old_delay = state->movement_delay;
		state->movement_delay--;
		ready = state->movement_delay == 0;
		state->registers.f = PORT_FLAG_N;
		if (ready)
			state->registers.f |= PORT_FLAG_Z;
		if ((old_delay & 0x0f) == 0)
			state->registers.f |= PORT_FLAG_H;
	}
	if (ready)
		state->movement_status = 1;
	state->registers.h = 0xc1;
	state->registers.a = state->current_offset;
	add_immediate(&state->registers, 8);
	state->registers.l = state->registers.a;
	state->animation_frame = 0;
	state->dispatched = 1;
}

/* Port of UpdateSpriteMovementDelay in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_update_sprite_movement_delay(
	struct sprite_movement_delay_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_globals[5])
{
	port_update_sprite_movement_delay_begin(state);
	/* JP UpdateSpriteImage is an arbitrary continuation boundary. */
	state->registers = *callback_registers;
	state->current_offset = callback_globals[0];
	state->movement_byte = callback_globals[1];
	state->movement_delay = callback_globals[2];
	state->movement_status = callback_globals[3];
	state->animation_frame = callback_globals[4];
}
