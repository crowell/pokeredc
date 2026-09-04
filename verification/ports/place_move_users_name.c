#include "port_state.h"

#define H_WHOSE_TURN 0xfff3u
#define W_BATTLE_MON_NICK 0xd009u
#define W_ENEMY_MON_NICK 0xcfda
#define ENEMY_TEXT 0x1a72u
#define TEXT_END 0x50u
#define ENEMY_TEXT_LENGTH 7u

void port_place_string(struct cpu_register_state *, port_u8 *);
void port_place_command_character(struct place_command_character_state *, port_u8 *);

static const port_u8 enemy_text[] = { 0x84, 0xad, 0xa4, 0xac, 0xb8, 0x7f, TEXT_END };

/* Shared body entered by PlaceMoveUsersName and PlaceMoveTargetsName after
 * their respective turn selection. */
static void
place_move_users_name_for_turn(struct place_move_users_name_state *state,
	port_u8 *memory, port_u8 whose_turn)
{
	port_u16 destination;
	port_u16 saved_de;

	if (whose_turn == 0u)
	{
		state->registers.d = (port_u8)(W_BATTLE_MON_NICK >> 8);
		state->registers.e = (port_u8)W_BATTLE_MON_NICK;
		port_place_command_character(
			(struct place_command_character_state *)state, memory);
		return;
	}

	for (port_u8 i = 0; i < ENEMY_TEXT_LENGTH; ++i)
		memory[ENEMY_TEXT + i] = enemy_text[i];
	state->registers.d = (port_u8)(ENEMY_TEXT >> 8);
	state->registers.e = (port_u8)ENEMY_TEXT;
	port_place_string(&state->registers, memory);
	destination = (port_u16)((port_u16)(state->registers.b << 8) |
	    state->registers.c);
	state->registers.h = (port_u8)(destination >> 8);
	state->registers.l = (port_u8)destination;
	state->registers.d = (port_u8)(W_ENEMY_MON_NICK >> 8);
	state->registers.e = (port_u8)W_ENEMY_MON_NICK;
	port_place_string(&state->registers, memory);
	destination = (port_u16)((port_u16)(state->registers.b << 8) |
	    state->registers.c);
	state->registers.h = (port_u8)(destination >> 8);
	state->registers.l = (port_u8)destination;
	saved_de = (port_u16)((port_u16)(state->saved_d << 8) | state->saved_e);
	saved_de = (port_u16)(saved_de + 1u);
	state->registers.d = (port_u8)(saved_de >> 8);
		state->registers.e = (port_u8)saved_de;
}

/* Port of PlaceMoveUsersName in home/text.asm. */
__attribute__((noinline, used)) void
port_place_move_users_name(struct place_move_users_name_state *state,
	port_u8 *memory)
{
	place_move_users_name_for_turn(state, memory, memory[H_WHOSE_TURN]);
}

/* Port of PlaceMoveTargetsName in home/text.asm: select the opposing side,
 * then enter PlaceMoveUsersName's shared `.place` body. */
__attribute__((noinline, used)) void
port_place_move_targets_name(struct place_move_users_name_state *state,
	port_u8 *memory)
{
	place_move_users_name_for_turn(state, memory,
	    (port_u8)(memory[H_WHOSE_TURN] ^ 1u));
}
