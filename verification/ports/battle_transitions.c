#include "port_state.h"

static void
port_transition_cp(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	port_u8 result = left - right;

	registers->f = PORT_FLAG_N;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

/* Port of GetBattleTransitionID_WildOrTrainer. */
__attribute__((noinline, used)) void
port_get_battle_transition_id_wild_or_trainer(
	struct transition_opponent_state *state)
{
	port_u8 value;

	state->registers.a = state->current_opponent;
	value = state->registers.a;
	state->registers.f = PORT_FLAG_N;
	if (value == 200)
		state->registers.f |= PORT_FLAG_Z;
	if ((value & 0x0f) < 8)
		state->registers.f |= PORT_FLAG_H;
	if (value < 200) {
		state->registers.f |= PORT_FLAG_C;
		state->registers.c &= (port_u8)~1;
	} else {
		state->registers.c |= 1;
	}
}

/* Port of GetBattleTransitionID_CompareLevels. */
__attribute__((noinline, used)) void
port_get_battle_transition_id_compare_levels(
	struct transition_level_state *state)
{
	port_u8 slot = 0;
	port_u8 threshold;
	port_u16 hl = 0xd16c;

	do {
		state->registers.a = state->party_hp[slot * 2];
		hl++;
		state->registers.a |= state->party_hp[slot * 2 + 1];
		if (state->registers.a != 0)
			break;
		state->registers.d = 0;
		state->registers.e = 0x2b;
		hl += 0x2b;
		slot++;
	} while (1);

	state->registers.d = 0;
	state->registers.e = 0x1f;
	hl += 0x1f;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = state->party_levels[slot];
	state->registers.a += 3;
	state->registers.e = state->registers.a;
	threshold = state->registers.e;
	state->registers.a = state->enemy_level;
	state->registers.f = PORT_FLAG_N;
	if (state->registers.a == threshold)
		state->registers.f |= PORT_FLAG_Z;
	if ((state->registers.a & 0x0f) < (threshold & 0x0f))
		state->registers.f |= PORT_FLAG_H;
	if (state->registers.a < threshold) {
		state->registers.f |= PORT_FLAG_C;
		state->registers.c &= (port_u8)~2;
		state->registers.a = 1;
		state->spiral_direction = 1;
	} else {
		state->registers.c |= 2;
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z;
		state->spiral_direction = 0;
	}
}

/* Port of GetBattleTransitionID_IsDungeonMap. */
__attribute__((noinline, used)) void
port_get_battle_transition_id_is_dungeon_map(
	struct transition_dungeon_state *state)
{
	static const port_u8 exact_maps[] = {0x33, 0x52, 0xc0, 0xe8, 0xff};
	static const port_u8 map_ranges[] = {
		0x3b, 0x3d, 0x5f, 0x76, 0x8d, 0x97, 0xcf, 0xe4, 0xff,
	};
	port_u8 index = 0;
	port_u16 hl;

	state->registers.a = state->current_map;
	state->registers.e = state->registers.a;
	hl = 0x4a3f;
	for (;;) {
		state->registers.a = exact_maps[index++];
		hl++;
		port_transition_cp(&state->registers, 0xff);
		if (state->registers.a == 0xff)
			break;
		port_transition_cp(&state->registers, state->registers.e);
		if (state->registers.a == state->registers.e) {
			state->registers.c |= 4;
			state->registers.h = (port_u8)(hl >> 8);
			state->registers.l = (port_u8)hl;
			return;
		}
	}

	index = 0;
	hl = 0x4a44;
	for (;;) {
		state->registers.a = map_ranges[index++];
		hl++;
		port_transition_cp(&state->registers, 0xff);
		if (state->registers.a == 0xff)
			break;
		state->registers.d = state->registers.a;
		state->registers.a = map_ranges[index++];
		hl++;
		port_transition_cp(&state->registers, state->registers.e);
		if (state->registers.a < state->registers.e)
			continue;
		state->registers.a = state->registers.e;
		port_transition_cp(&state->registers, state->registers.d);
		if (state->registers.a >= state->registers.d) {
			state->registers.c |= 4;
			state->registers.h = (port_u8)(hl >> 8);
			state->registers.l = (port_u8)hl;
			return;
		}
		break;
	}

	state->registers.c &= (port_u8)~4;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}

/* Port of BattleTransition_BlackScreen. */
__attribute__((noinline, used)) void
port_battle_transition_black_screen(struct black_screen_state *state)
{
	state->registers.a = 0xff;
	state->background_palette = state->registers.a;
	state->object_palette0 = state->registers.a;
	state->object_palette1 = state->registers.a;
}

static port_u16
outward_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
outward_add_hl(struct cpu_register_state *registers, port_u16 right)
{
	port_u16 left = outward_pair(registers->h, registers->l);
	unsigned int wide = (unsigned int)left + right;

	registers->h = (port_u8)(wide >> 8);
	registers->l = (port_u8)wide;
	registers->f &= PORT_FLAG_Z;
	if ((left & 0x0fff) + (right & 0x0fff) > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xffff)
		registers->f |= PORT_FLAG_C;
}

/* Port of BattleTransition_OutwardSpiral_. */
__attribute__((noinline, used)) void
port_battle_transition_outward_spiral_step(
	struct outward_spiral_step_state *state)
{
	port_u16 candidate;
	port_u8 direction;

	state->registers.b = 0xff;
	state->registers.c = 0xec;
	state->registers.d = 0;
	state->registers.e = 0x14;
	state->registers.a = state->pointer_low;
	state->registers.l = state->registers.a;
	state->registers.a = state->pointer_high;
	state->registers.h = state->registers.a;
	state->registers.a = state->direction;
	direction = state->registers.a;
	port_transition_cp(&state->registers, 0);
	if (direction == 0) {
		candidate = (port_u16)(outward_pair(state->registers.h,
			state->registers.l) - 1);
	} else {
		port_transition_cp(&state->registers, 1);
		if (direction == 1)
			candidate = (port_u16)(outward_pair(state->registers.h,
				state->registers.l) + 20);
		else {
			port_transition_cp(&state->registers, 2);
			if (direction == 2)
				candidate = (port_u16)(outward_pair(state->registers.h,
					state->registers.l) + 1);
			else {
				port_transition_cp(&state->registers, 3);
				if (direction == 3)
					candidate = (port_u16)(outward_pair(
						state->registers.h,
						state->registers.l) - 20);
				else
					goto keep_direction;
			}
		}
	}
	state->registers.h = (port_u8)(candidate >> 8);
	state->registers.l = (port_u8)candidate;
	state->registers.a = state->probed;
	port_transition_cp(&state->registers, 0xff);
	if (state->registers.a != 0xff)
		goto change_direction;
	if (direction == 0) {
		candidate++;
		state->registers.h = (port_u8)(candidate >> 8);
		state->registers.l = (port_u8)candidate;
		outward_add_hl(&state->registers, 0xffec);
	} else if (direction == 1) {
		outward_add_hl(&state->registers, 0xffec);
		candidate = (port_u16)(outward_pair(state->registers.h,
			state->registers.l) - 1);
		state->registers.h = (port_u8)(candidate >> 8);
		state->registers.l = (port_u8)candidate;
	} else if (direction == 2) {
		candidate--;
		state->registers.h = (port_u8)(candidate >> 8);
		state->registers.l = (port_u8)candidate;
		outward_add_hl(&state->registers, 20);
	} else {
		outward_add_hl(&state->registers, 20);
		candidate = (port_u16)(outward_pair(state->registers.h,
			state->registers.l) + 1);
		state->registers.h = (port_u8)(candidate >> 8);
		state->registers.l = (port_u8)candidate;
	}
keep_direction:
	state->written = 0xff;
	state->write_h = state->registers.h;
	state->write_l = state->registers.l;
	goto done;
change_direction:
	state->written = 0xff;
	state->write_h = state->registers.h;
	state->write_l = state->registers.l;
	state->registers.a = state->direction;
	{
		port_u8 old = state->registers.a;
		state->registers.a++;
		state->registers.f &= PORT_FLAG_C;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((old & 0x0f) == 0x0f)
			state->registers.f |= PORT_FLAG_H;
	}
	port_transition_cp(&state->registers, 4);
	if (state->registers.a == 4) {
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z;
	}
	state->direction = state->registers.a;
done:
	state->registers.a = state->registers.l;
	state->pointer_low = state->registers.a;
	state->registers.a = state->registers.h;
	state->pointer_high = state->registers.a;
}

static void
circle_and_a(struct cpu_register_state *registers)
{
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
circle_dec_c(struct cpu_register_state *registers)
{
	port_u8 old = registers->c;
	port_u8 carry = registers->f & PORT_FLAG_C;

	registers->c--;
	registers->f = carry | PORT_FLAG_N;
	if (registers->c == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

/* Enters the first horizontal span. */
__attribute__((noinline, used)) port_u8
port_battle_transition_circle_entry(struct circle_transition_state *state)
{
	port_u16 de = outward_pair(state->registers.d, state->registers.e);

	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;
	state->registers.a = state->fetched;
	state->registers.c = state->registers.a;
	de++;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	return 1;
}

/* Returns 1 to repeat the first span, or 0 to advance to the next row. */
__attribute__((noinline, used)) port_u8
port_battle_transition_circle_loop1_step(struct circle_transition_state *state)
{
	port_u16 hl = outward_pair(state->registers.h, state->registers.l);

	state->written = 0xff;
	state->write_h = state->registers.h;
	state->write_l = state->registers.l;
	state->registers.a = state->quadrant_x;
	circle_and_a(&state->registers);
	if (state->registers.a == 0)
		hl--;
	else
		hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	circle_dec_c(&state->registers);
	if (state->registers.c != 0)
		return 1;
	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
	return 0;
}

/* Returns 0 for RET, 2 to restart, or 3 to enter the second span. */
__attribute__((noinline, used)) port_u8
port_battle_transition_circle_row(struct circle_transition_state *state)
{
	port_u16 de = outward_pair(state->registers.d, state->registers.e);

	state->registers.a = state->quadrant_y;
	circle_and_a(&state->registers);
	state->registers.b = state->registers.a == 0 ? 0 : 0xff;
	state->registers.c = state->registers.a == 0 ? 20 : 0xec;
	outward_add_hl(&state->registers,
		outward_pair(state->registers.b, state->registers.c));
	state->registers.a = state->fetched;
	de++;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	port_transition_cp(&state->registers, 0xff);
	if (state->registers.a == 0xff)
		return 0;
	circle_and_a(&state->registers);
	if (state->registers.a == 0)
		return 2;
	state->registers.c = state->registers.a;
	return 3;
}

/* Returns 3 to repeat the second span, or 2 to restart at the next run. */
__attribute__((noinline, used)) port_u8
port_battle_transition_circle_loop2_step(struct circle_transition_state *state)
{
	port_u16 hl;

	state->registers.a = state->quadrant_x;
	circle_and_a(&state->registers);
	hl = outward_pair(state->registers.h, state->registers.l);
	if (state->registers.a == 0)
		hl++;
	else
		hl--;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	circle_dec_c(&state->registers);
	return state->registers.c == 0 ? 2 : 3;
}

/* Port of BattleTransition_Circle_Sub3. */
__attribute__((noinline, used)) void
port_battle_transition_circle_sub3(
	struct circle_transition_state *state, port_u8 *memory)
{
	port_u8 continuation;
	port_u16 address;

	for (;;) {
		address = outward_pair(state->registers.d, state->registers.e);
		state->fetched = memory[address];
		continuation = port_battle_transition_circle_entry(state);
		while (continuation == 1) {
			address = outward_pair(state->registers.h,
				state->registers.l);
			continuation =
				port_battle_transition_circle_loop1_step(state);
			memory[address] = state->written;
		}
		address = outward_pair(state->registers.d, state->registers.e);
		state->fetched = memory[address];
		continuation = port_battle_transition_circle_row(state);
		if (continuation == 0)
			return;
		while (continuation == 3)
			continuation =
				port_battle_transition_circle_loop2_step(state);
	}
}

static void
copy2_add_a(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	unsigned int wide = (unsigned int)left + right;

	registers->a = (port_u8)wide;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xff)
		registers->f |= PORT_FLAG_C;
}

static void
copy2_add_hl(struct cpu_register_state *registers, port_u16 right)
{
	port_u16 left = outward_pair(registers->h, registers->l);
	unsigned int wide = (unsigned int)left + right;

	registers->h = (port_u8)(wide >> 8);
	registers->l = (port_u8)wide;
	registers->f &= PORT_FLAG_Z;
	if ((left & 0x0fff) + (right & 0x0fff) > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xffff)
		registers->f |= PORT_FLAG_C;
}

static void
copy2_dec_c(struct cpu_register_state *registers)
{
	port_u8 old = registers->c;
	port_u8 carry = registers->f & PORT_FLAG_C;

	registers->c--;
	registers->f = carry | PORT_FLAG_N;
	if (registers->c == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

__attribute__((noinline, used)) port_u8
port_battle_transition_copy_tiles2_setup(
	struct transition_copy_tiles2_state *state)
{
	state->registers.a = state->registers.c;
	state->offset_low = state->registers.a;
	state->registers.a = state->registers.b;
	state->offset_high = state->registers.a;
	state->registers.c = 9;
	return 1;
}

__attribute__((noinline, used)) void
port_battle_transition_copy_tiles2_row_begin(
	struct transition_copy_tiles2_state *state)
{
	state->saved_b = state->registers.b;
	state->saved_c = state->registers.c;
	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;
	state->saved_d = state->registers.d;
	state->saved_e = state->registers.e;
	state->registers.c = 18;
}

/* Returns 1 for another vertical byte or 0 after eighteen bytes. */
__attribute__((noinline, used)) port_u8
port_battle_transition_copy_tiles2_inner_step(
	struct transition_copy_tiles2_state *state)
{
	state->registers.a = state->fetched;
	state->written = state->registers.a;
	state->write_h = state->registers.d;
	state->write_l = state->registers.e;
	state->registers.a = state->registers.e;
	copy2_add_a(&state->registers, 20);
	if (state->registers.f & PORT_FLAG_C)
		state->registers.d++;
	state->registers.e = state->registers.a;
	state->registers.a = state->registers.l;
	copy2_add_a(&state->registers, 20);
	if (state->registers.f & PORT_FLAG_C)
		state->registers.h++;
	state->registers.l = state->registers.a;
	copy2_dec_c(&state->registers);
	return state->registers.c == 0 ? 0 : 1;
}

/* Returns 1 for another outer column or 2 to enter the final fill. */
__attribute__((noinline, used)) port_u8
port_battle_transition_copy_tiles2_outer_finish(
	struct transition_copy_tiles2_state *state)
{
	state->registers.h = state->saved_d;
	state->registers.l = state->saved_e;
	state->registers.d = state->saved_h;
	state->registers.e = state->saved_l;
	state->registers.a = state->offset_low;
	state->registers.c = state->registers.a;
	state->registers.a = state->offset_high;
	state->registers.b = state->registers.a;
	copy2_add_hl(&state->registers,
		outward_pair(state->registers.b, state->registers.c));
	state->registers.b = state->saved_b;
	state->registers.c = state->saved_c;
	copy2_dec_c(&state->registers);
	if (state->registers.c != 0)
		return 1;
	state->registers.l = state->registers.e;
	state->registers.h = state->registers.d;
	state->registers.d = 0;
	state->registers.e = 20;
	state->registers.c = 18;
	return 2;
}

/* Returns 2 for another fill byte or 0 after eighteen rows. */
__attribute__((noinline, used)) port_u8
port_battle_transition_copy_tiles2_fill_step(
	struct transition_copy_tiles2_state *state)
{
	state->written = 0xff;
	state->write_h = state->registers.h;
	state->write_l = state->registers.l;
	copy2_add_hl(&state->registers,
		outward_pair(state->registers.d, state->registers.e));
	copy2_dec_c(&state->registers);
	return state->registers.c == 0 ? 0 : 2;
}

/* Port of BattleTransition_CopyTiles2. */
__attribute__((noinline, used)) void
port_battle_transition_copy_tiles2(
	struct transition_copy_tiles2_state *state, port_u8 *memory)
{
	port_u8 continuation = port_battle_transition_copy_tiles2_setup(state);
	port_u16 source;
	port_u16 address;

	while (continuation == 1) {
		port_battle_transition_copy_tiles2_row_begin(state);
		do {
			source = outward_pair(state->registers.h, state->registers.l);
			state->fetched = memory[source];
			continuation =
				port_battle_transition_copy_tiles2_inner_step(state);
			address = outward_pair(state->write_h, state->write_l);
			memory[address] = state->written;
		} while (continuation != 0);
		continuation =
			port_battle_transition_copy_tiles2_outer_finish(state);
	}
	while (continuation == 2) {
		continuation = port_battle_transition_copy_tiles2_fill_step(state);
		address = outward_pair(state->write_h, state->write_l);
		memory[address] = state->written;
	}
}
