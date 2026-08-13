#include "port_state.h"

static void
trainer_header_cp(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	port_u8 result = (port_u8)(left - right);

	registers->f = PORT_FLAG_N;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

/* Port of ReadTrainerHeaderInfo in home/trainers.asm. */
__attribute__((noinline, used)) void
port_read_trainer_header_info(struct trainer_header_info_state *state)
{
	port_u8 offset = state->registers.a;
	port_u8 saved_d = state->registers.d;
	port_u8 saved_e = state->registers.e;
	port_u16 hl = (port_u16)(((port_u16)state->header_high << 8) |
		state->header_low);
	port_u8 pointer = 0;

	state->registers.d = 0;
	state->registers.e = offset;
	hl = (port_u16)(hl + offset);
	state->registers.a = offset;
	state->registers.f = PORT_FLAG_H;
	if (offset == 0) {
		state->registers.f |= PORT_FLAG_Z;
		state->registers.a = state->fetched_first;
		state->flag_bit = state->registers.a;
	} else {
		trainer_header_cp(&state->registers, 2);
		if (offset == 2)
			pointer = 1;
		else {
			trainer_header_cp(&state->registers, 4);
			if (offset == 4)
				pointer = 1;
			else {
				trainer_header_cp(&state->registers, 6);
				if (offset == 6)
					pointer = 1;
				else {
					trainer_header_cp(&state->registers, 8);
					if (offset == 8)
						pointer = 1;
					else
						trainer_header_cp(&state->registers, 10);
				}
			}
		}
		if (pointer) {
			state->registers.a = state->fetched_first;
			state->registers.h = state->fetched_second;
			state->registers.l = state->registers.a;
			hl = (port_u16)(((port_u16)state->registers.h << 8) |
				state->registers.l);
		} else if (offset == 10) {
			state->registers.a = state->fetched_first;
			hl++;
			state->registers.d = state->fetched_second;
			state->registers.e = state->registers.a;
		}
	}
	state->registers.d = saved_d;
	state->registers.e = saved_e;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}
