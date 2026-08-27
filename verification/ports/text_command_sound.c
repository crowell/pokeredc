#include "port_state.h"

#define TEXT_COMMAND_SOUNDS 0x1c64u
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u

#define TX_SOUND_CRY_NIDORINA 0x14u
#define TX_SOUND_CRY_PIDGEOT 0x15u
#define TX_SOUND_CRY_DEWGONG 0x16u

void port_play_sound(struct play_sound_state *);
void port_wait_for_sound_to_finish(struct wait_for_sound_state *);
void port_play_cry(struct play_sound_state *, port_u8 *);

static const port_u8 text_command_sounds[10][2] = {
	{ 0x0bu, 0x86u },
	{ 0x12u, 0x9au },
	{ 0x0eu, 0x91u },
	{ 0x0fu, 0x86u },
	{ 0x10u, 0x89u },
	{ 0x11u, 0x94u },
	{ 0x13u, 0x98u },
	{ TX_SOUND_CRY_NIDORINA, 0xa8u },
	{ TX_SOUND_CRY_PIDGEOT, 0x97u },
	{ TX_SOUND_CRY_DEWGONG, 0x78u },
};

static void
sound_cp(struct cpu_register_state *state, port_u8 value)
{
	port_u8 left = state->a;
	port_u8 result = (port_u8)(left - value);

	state->f = PORT_FLAG_N;
	if (result == 0)
		state->f |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (value & 0x0fu))
		state->f |= PORT_FLAG_H;
	if (left < value)
		state->f |= PORT_FLAG_C;
}

static void
sound_wait(struct play_sound_state *state)
{
	struct wait_for_sound_state wait;

	wait.registers = state->registers;
	wait.low_health_alarm = state->low_health_alarm;
	wait.channel_sound_ids[0] = state->channel_sound_ids[0];
	wait.channel_sound_ids[1] = state->channel_sound_ids[1];
	wait.channel_sound_ids[2] = state->channel_sound_ids[3];
	port_wait_for_sound_to_finish(&wait);
	state->registers = wait.registers;
	state->channel_sound_ids[0] = wait.channel_sound_ids[0];
	state->channel_sound_ids[1] = wait.channel_sound_ids[1];
	state->channel_sound_ids[3] = wait.channel_sound_ids[2];
}

/* Port of TextCommand_SOUND in home/text.asm. The dispatcher-pushed text
 * pointer is represented by entry HL, which points just after the command. */
__attribute__((noinline, used)) void
port_text_command_sound(struct play_sound_state *state, port_u8 *memory)
{
	port_u16 text = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 saved_b = state->registers.b;
	port_u8 saved_c = state->registers.c;
	port_u8 saved_d = state->registers.d;
	port_u8 saved_e = state->registers.e;
	port_u8 command = memory[(port_u16)(text - 1u)];
	port_u8 index;

	state->registers.a = command;
	state->registers.b = command;
	for (index = 0; index != 10u; index++) {
		state->registers.h = (port_u8)(
			(TEXT_COMMAND_SOUNDS + (port_u16)(index * 2u) + 1u) >> 8);
		state->registers.l = (port_u8)(
			TEXT_COMMAND_SOUNDS + (port_u16)(index * 2u) + 1u);
		state->registers.a = text_command_sounds[index][0];
		sound_cp(&state->registers, state->registers.b);
		if (state->registers.a == state->registers.b)
			break;
	}

	sound_cp(&state->registers, TX_SOUND_CRY_NIDORINA);
	if (state->registers.a != TX_SOUND_CRY_NIDORINA) {
		sound_cp(&state->registers, TX_SOUND_CRY_PIDGEOT);
		if (state->registers.a != TX_SOUND_CRY_PIDGEOT)
			sound_cp(&state->registers, TX_SOUND_CRY_DEWGONG);
	}
	if (state->registers.a == TX_SOUND_CRY_NIDORINA ||
	    state->registers.a == TX_SOUND_CRY_PIDGEOT ||
	    state->registers.a == TX_SOUND_CRY_DEWGONG) {
		state->registers.a = text_command_sounds[index][1];
		port_play_cry(state, memory);
		state->registers.d = saved_d;
		state->registers.e = saved_e;
	} else {
		state->registers.a = text_command_sounds[index][1];
		port_play_sound(state);
		memory[H_LOADED_ROM_BANK] = state->loaded_rom_bank;
		memory[R_ROMB] = state->rom_bank;
		sound_wait(state);
	}
	state->registers.h = (port_u8)(text >> 8);
	state->registers.l = (port_u8)text;
	state->registers.b = saved_b;
	state->registers.c = saved_c;
}
