#include "port_state.h"

#define MOVE_SOUND_TABLE 0x58bcu
#define MOVE_SOUND_TABLE_SIZE 768u
#define GROWL 0x2du
#define ROAR 0x2eu

struct get_move_sound_state {
	struct cpu_register_state registers;
	port_u8 frequency_modifier;
	port_u8 tempo_modifier;
	port_u8 animation_id;
	port_u8 whose_turn;
	port_u8 battle_mon_species;
	port_u8 enemy_mon_species;
	/* Explicit result and memory effects of the GetCryData callee. */
	port_u8 cry_a;
	port_u8 cry_b;
	port_u8 cry_c;
	port_u8 cry_frequency_modifier;
	port_u8 cry_tempo_modifier;
	port_u8 move_sound_table[MOVE_SOUND_TABLE_SIZE];
};

static port_u8
add_flags(port_u8 left, port_u8 right, port_u8 result)
{
	port_u8 flags = 0;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if (((left & 0x0f) + (right & 0x0f)) > 0x0f)
		flags |= PORT_FLAG_H;
	if ((port_u16)left + right > 0xff)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of GetMoveSound in engine/battle/animations.asm.
 *
 * The MoveSoundTable bytes are explicit state so every 8-bit move ID, including
 * the table's masked-out ROM window, remains part of the pathwise contract.
 * GetCryData is an explicit compositional boundary: its returned A/C and the
 * two modifier writes are state inputs, while GetMoveSound retains its exact
 * register and modifier updates around that call.
 */
__attribute__((noinline, used)) void
port_get_move_sound(struct get_move_sound_state *state)
{
	port_u8 move_id = state->registers.a;
	port_u16 table_offset = (port_u16)move_id * 3u;
	port_u8 sound = state->move_sound_table[table_offset];
	port_u8 table_frequency = state->move_sound_table[table_offset + 1];
	port_u8 table_tempo = state->move_sound_table[table_offset + 2];

	state->registers.d = 0;
	state->registers.e = move_id;
	state->registers.b = sound;
	state->registers.h = (port_u8)(MOVE_SOUND_TABLE >> 8);
	state->registers.l = (port_u8)MOVE_SOUND_TABLE;

	if (state->animation_id == GROWL || state->animation_id == ROAR) {
		port_u8 frequency = (port_u8)(state->cry_frequency_modifier + table_frequency);
		port_u8 tempo = (port_u8)(state->cry_tempo_modifier + table_tempo);

		state->registers.a = state->cry_a;
		state->registers.b = state->registers.a;
		state->registers.c = state->cry_c;
		state->frequency_modifier = frequency;
		state->tempo_modifier = tempo;
		state->registers.f = add_flags(state->cry_tempo_modifier,
		    table_tempo, tempo);
		{
			port_u16 pointer = (port_u16)(MOVE_SOUND_TABLE + table_offset + 2u);
			state->registers.h = (port_u8)(pointer >> 8);
			state->registers.l = (port_u8)pointer;
		}
		return;
	}
	state->frequency_modifier = table_frequency;
	state->tempo_modifier = table_tempo;
	state->registers.a = state->registers.b;
	state->registers.f = state->animation_id == 0 ? PORT_FLAG_Z : 0;
	{
		port_u16 pointer = (port_u16)(MOVE_SOUND_TABLE + table_offset + 3u);
		state->registers.h = (port_u8)(pointer >> 8);
		state->registers.l = (port_u8)pointer;
	}
}
