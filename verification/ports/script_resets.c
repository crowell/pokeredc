#include "port_state.h"

static void
move_gate_player(struct gate_movement_state *state, port_u8 direction)
{
	state->registers.h = 0xd7;
	state->registers.l = 0x30;
	state->status_flags5 |= 0x80;
	state->registers.a = direction;
	state->joypad_end = state->registers.a;
	state->registers.a = 1;
	state->joypad_index = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->movement_byte1 = 0;
	state->override_mask = 0;
}

__attribute__((noinline, used)) void
port_route_6_gate_move_player_down(struct gate_movement_state *state)
{
	move_gate_player(state, 0x80);
}

__attribute__((noinline, used)) void
port_route_7_gate_move_player_left(struct gate_movement_state *state)
{
	move_gate_player(state, 0x20);
}

__attribute__((noinline, used)) void
port_route_8_gate_move_player_right(struct gate_movement_state *state)
{
	move_gate_player(state, 0x10);
}

static __attribute__((noinline)) void
script_reset(struct script_reset_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->joy_ignore = 0;
	state->current_script = 0;
	state->current_map_script = 0;
}

#define DEFINE_SCRIPT_RESET_PORT(name) \
	__attribute__((noinline, used)) void name(struct script_reset_state *state) \
	{ \
		script_reset(state); \
	}

/* Ports of the identical five-instruction map-script reset leaves. */
DEFINE_SCRIPT_RESET_PORT(port_celadon_gym_reset_scripts)
DEFINE_SCRIPT_RESET_PORT(port_cerulean_gym_reset_scripts)
DEFINE_SCRIPT_RESET_PORT(port_fighting_dojo_reset_scripts)
DEFINE_SCRIPT_RESET_PORT(port_fuchsia_gym_reset_scripts)
DEFINE_SCRIPT_RESET_PORT(port_game_corner_reenter_map_after_player_loss)
DEFINE_SCRIPT_RESET_PORT(port_mt_moon_b2f_reset_scripts)
DEFINE_SCRIPT_RESET_PORT(port_pewter_gym_reset_scripts)
DEFINE_SCRIPT_RESET_PORT(port_pokemon_tower_2f_reset_rival_encounter)
DEFINE_SCRIPT_RESET_PORT(port_pokemon_tower_6f_set_default_script)
DEFINE_SCRIPT_RESET_PORT(port_pokemon_tower_7f_set_default_script)
DEFINE_SCRIPT_RESET_PORT(port_rocket_hideout_b4f_set_default_script)
DEFINE_SCRIPT_RESET_PORT(port_route_12_reset_scripts)
DEFINE_SCRIPT_RESET_PORT(port_route_16_reset_scripts)
DEFINE_SCRIPT_RESET_PORT(port_route_24_set_default_script)
DEFINE_SCRIPT_RESET_PORT(port_saffron_gym_reset_scripts)
DEFINE_SCRIPT_RESET_PORT(port_vermilion_gym_reset_scripts)
DEFINE_SCRIPT_RESET_PORT(port_viridian_gym_reset_scripts)
DEFINE_SCRIPT_RESET_PORT(port_silph_co_11f_reset_cur_script)
DEFINE_SCRIPT_RESET_PORT(port_silph_co_7f_set_default_script)

static __attribute__((noinline)) void
zero_stores(struct zero_stores_state *state, port_u8 count)
{
	port_u8 index;

	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	for (index = 0; index < count; index++)
		state->memory[index] = 0;
}

#define DEFINE_ZERO_STORES_PORT(name, count) \
	__attribute__((noinline, used)) void name(struct zero_stores_state *state) \
	{ \
		zero_stores(state, count); \
	}

DEFINE_ZERO_STORES_PORT(port_reset_agatha_script, 1)
DEFINE_ZERO_STORES_PORT(port_reset_bruno_script, 1)
DEFINE_ZERO_STORES_PORT(port_reset_rival_script, 2)
DEFINE_ZERO_STORES_PORT(port_cinnabar_gym_reset_scripts, 4)
DEFINE_ZERO_STORES_PORT(port_reset_lance_script, 1)
DEFINE_ZERO_STORES_PORT(port_reset_lorelei_script, 1)
DEFINE_ZERO_STORES_PORT(port_ss_anne_2f_reset_scripts, 2)
DEFINE_ZERO_STORES_PORT(port_route_22_set_default_script, 2)

/* Port of ExecutePlayerMoveDone in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_execute_player_move_done(struct zero_stores_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->memory[0] = 0;
	state->registers.b = 1;
}

/* Port of ItemUseFailed through its PrintText tail boundary. */
__attribute__((noinline, used)) void
port_item_use_failed(struct zero_stores_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->memory[0] = 0;
}

/* Port of ResetButtonPressedAndMapScript in home/trainers.asm. */
__attribute__((noinline, used)) void
port_reset_button_pressed_and_map_script(struct button_reset_state *state)
{
	port_u8 index;

	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	for (index = 0; index < 5; index++)
		state->memory[index] = 0;
}

/* Port of StartSimulatingJoypadStates in home/map_objects.asm. */
__attribute__((noinline, used)) void
port_start_simulating_joypad_states(struct zero_stores_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->memory[0] = 0;
	state->memory[1] = 0;
	state->registers.h = 0xd7;
	state->registers.l = 0x30;
	state->memory[2] |= 0x80;
}
