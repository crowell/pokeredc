#include "port_state.h"

static void
alarm_bit7(struct cpu_register_state *registers)
{
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_H;
	if ((registers->a & 0x80) == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
alarm_and_timer(struct cpu_register_state *registers)
{
	registers->a &= 0x7f;
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
alarm_decrement(struct cpu_register_state *registers)
{
	port_u8 before = registers->a;

	registers->a--;
	registers->f = (registers->f & PORT_FLAG_C) | PORT_FLAG_N;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((before & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
alarm_play_tone(struct music_low_health_alarm_state *state,
	port_u16 address, const port_u8 data[5])
{
	port_u8 index;

	state->registers.h = 0xff;
	state->registers.l = 0x10;
	state->registers.c = 5;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	for (index = 0; index < 5; index++) {
		state->audio1_registers[index] = state->registers.a;
		state->registers.l++;
		state->registers.a = data[index];
		address++;
		state->registers.c--;
	}
	state->registers.d = (port_u8)(address >> 8);
	state->registers.e = (port_u8)address;
	state->registers.f = PORT_FLAG_Z | PORT_FLAG_N;
}

/* Port of Music_DoLowHealthAlarm in audio/low_health_alarm.asm. */
__attribute__((noinline, used)) void
port_music_do_low_health_alarm(struct music_low_health_alarm_state *state)
{
	static const port_u8 tone_high[5] = {0xa0, 0xe2, 0x50, 0x87, 0xb0};
	static const port_u8 tone_low[5] = {0xb0, 0xe2, 0xee, 0x86, 0x00};
	static const port_u8 tone_silence[5] = {0x00, 0x00, 0x00, 0x80, 0xaf};
	port_u8 timer;

	state->registers.a = state->low_health_alarm;
	if (state->registers.a == 0xff) {
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z;
		state->low_health_alarm = 0;
		state->channel5_sound_id = 0;
		state->registers.d = 0x53;
		state->registers.e = 0xc4;
		alarm_play_tone(state, 0x53c4, tone_silence);
		return;
	}

	/* CP $ff leaves carry set for every remaining accumulator value. */
	state->registers.f = PORT_FLAG_C;
	alarm_bit7(&state->registers);
	if ((state->registers.a & 0x80) == 0)
		return;
	alarm_and_timer(&state->registers);
	timer = state->registers.a;
	if (timer == 0) {
		state->registers.d = 0x53;
		state->registers.e = 0xbc;
		alarm_play_tone(state, 0x53bc, tone_high);
		state->registers.a = 30;
	} else {
		if (timer == 20) {
			state->registers.d = 0x53;
			state->registers.e = 0xc0;
			alarm_play_tone(state, 0x53c0, tone_low);
		}
		state->registers.a = 0x86;
		state->channel5_sound_id = state->registers.a;
		state->registers.a = state->low_health_alarm;
		alarm_and_timer(&state->registers);
		alarm_decrement(&state->registers);
	}
	state->registers.a |= 0x80;
	state->low_health_alarm = state->registers.a;
}
