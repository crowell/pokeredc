#include "port_state.h"

static const port_u8 move_choice_table[] = {
	0x00,0x01,0x00,0x01,0x00,0x01,0x03,0x00,0x01,0x00,0x01,0x00,
	0x01,0x02,0x03,0x00,0x01,0x02,0x00,0x01,0x00,0x01,0x00,0x01,
	0x03,0x00,0x01,0x00,0x01,0x02,0x00,0x01,0x03,0x00,0x01,0x03,
	0x00,0x00,0x01,0x00,0x01,0x03,0x00,0x01,0x02,0x00,0x01,0x03,
	0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x01,
	0x03,0x00,0x01,0x02,0x00,0x01,0x02,0x00,0x01,0x03,0x00,0x01,
	0x00,0x01,0x03,0x00,0x01,0x03,0x00,0x01,0x00,0x01,0x00,0x01,
	0x03,0x00,0x01,0x03,0x00,0x01,0x03,0x00,0x01,0x03,0x00,0x01,
	0x03,0x00,0x01,0x03,0x00,0x01,0x02,0x00,0x01,0x03,0x00,0x01,
	0x03,0x00,0x01,0x02,0x03,0x00,0x01,0x00,0x01,0x00,0x01,0x03,
	0x00,
};

static port_u16
choice_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
choice_set_hl(struct cpu_register_state *r, port_u16 value)
{
	r->h = (port_u8)(value >> 8); r->l = (port_u8)value;
}

static void
choice_set_de(struct cpu_register_state *r, port_u16 value)
{
	r->d = (port_u8)(value >> 8); r->e = (port_u8)value;
}

static void
choice_and_a(struct cpu_register_state *r)
{
	r->f = PORT_FLAG_H | (r->a == 0 ? PORT_FLAG_Z : 0);
}

static void
choice_cp(struct cpu_register_state *r, port_u8 right)
{
	port_u8 left = r->a;
	r->f = PORT_FLAG_N;
	if (left == right) r->f |= PORT_FLAG_Z;
	if ((left & 15) < (right & 15)) r->f |= PORT_FLAG_H;
	if (left < right) r->f |= PORT_FLAG_C;
}

static void
choice_dec(struct cpu_register_state *r, port_u8 *value)
{
	port_u8 old = *value;
	port_u8 carry = r->f & PORT_FLAG_C;
	(*value)--;
	r->f = carry | PORT_FLAG_N;
	if (*value == 0) r->f |= PORT_FLAG_Z;
	if ((old & 15) == 0) r->f |= PORT_FLAG_H;
}

static void
choice_inc(struct cpu_register_state *r, port_u8 *value)
{
	port_u8 old = *value;
	port_u8 carry = r->f & PORT_FLAG_C;
	(*value)++;
	r->f = carry;
	if (*value == 0) r->f |= PORT_FLAG_Z;
	if ((old & 15) == 15) r->f |= PORT_FLAG_H;
}

static void
choice_add_hl(struct cpu_register_state *r, port_u16 right)
{
	port_u16 left = choice_pair(r->h, r->l);
	unsigned long wide = (unsigned long)left + right;
	port_u8 flags = r->f & PORT_FLAG_Z;
	if ((left & 0xfff) + (right & 0xfff) > 0xfff) flags |= PORT_FLAG_H;
	if (wide > 0xffff) flags |= PORT_FLAG_C;
	choice_set_hl(r, (port_u16)wide); r->f = flags;
}

static void
choice_add_immediate(struct cpu_register_state *r, port_u8 right)
{
	port_u8 left = r->a; unsigned wide = (unsigned)left + right;
	r->a = (port_u8)wide; r->f = 0;
	if (r->a == 0) r->f |= PORT_FLAG_Z;
	if ((left & 15) + (right & 15) > 15) r->f |= PORT_FLAG_H;
	if (wide > 255) r->f |= PORT_FLAG_C;
}

static void
choice_dec_memory(struct cpu_register_state *r, port_u8 old, port_u8 *written)
{
	port_u8 value = (port_u8)(old - 1); port_u8 carry = r->f & PORT_FLAG_C;
	r->f = carry | PORT_FLAG_N;
	if (value == 0) r->f |= PORT_FLAG_Z;
	if ((old & 15) == 0) r->f |= PORT_FLAG_H;
	*written = value;
}

__attribute__((noinline, used)) void
port_trainer_choose_moves_init(struct trainer_move_choice_state *s)
{
	port_u8 i;
	s->registers.a = 10; choice_set_hl(&s->registers, 0xcee9);
	for (i = 0; i != 4; i++) s->buffer[i] = s->registers.a;
	choice_set_hl(&s->registers, 0xceed);
	s->registers.a = s->disabled_move;
	/* SWAP A then AND 0xf. */
	s->registers.a = (port_u8)((s->registers.a << 4) | (s->registers.a >> 4));
	s->registers.f = s->registers.a == 0 ? PORT_FLAG_Z : 0;
	s->registers.a &= 15; s->registers.f = PORT_FLAG_H | (s->registers.a == 0 ? PORT_FLAG_Z : 0);
	if (s->registers.a != 0) {
		choice_set_hl(&s->registers, 0xcee9);
		choice_dec(&s->registers, &s->registers.a);
		s->registers.c = s->registers.a; s->registers.b = 0;
		choice_add_hl(&s->registers, s->registers.c);
		s->buffer[s->registers.c] = 0x50;
	}
}

__attribute__((noinline, used)) void
port_trainer_choose_moves_class_begin(struct trainer_move_choice_state *s)
{
	port_u16 offset = 0;
	port_u8 remaining = s->trainer_class;
	choice_set_hl(&s->registers, 0x589b);
	s->registers.a = s->trainer_class; s->registers.b = s->registers.a;
	do {
		s->registers.b = remaining;
		choice_dec(&s->registers, &s->registers.b);
		remaining = s->registers.b;
		if (remaining == 0) break;
		do {
			s->registers.a = move_choice_table[offset++];
			choice_and_a(&s->registers);
		} while (s->registers.a != 0);
	} while (1);
	choice_set_hl(&s->registers, (port_u16)(0x589b + offset));
}

/* Returns 1 to dispatch a modification, 0 when the zero terminator is read. */
__attribute__((noinline, used)) port_u8
port_trainer_choose_moves_modification(struct trainer_move_choice_state *s)
{
	port_u16 hl = (port_u16)(choice_pair(s->registers.h, s->registers.l) + 1);
	s->registers.a = s->modification;
	choice_and_a(&s->registers);
	choice_set_hl(&s->registers, hl);
	if (s->registers.a == 0) return 0;
	s->saved_h = s->registers.h; s->saved_l = s->registers.l;
	choice_dec(&s->registers, &s->registers.a);
	s->registers.a = (port_u8)(s->registers.a + s->registers.a);
	s->registers.f = s->registers.a == 0 ? PORT_FLAG_Z : 0;
	s->registers.c = s->registers.a; s->registers.b = 0;
	choice_set_hl(&s->registers, 0x57a3);
	choice_add_hl(&s->registers, s->registers.c);
	s->dispatched = 1;
	return 1;
}

__attribute__((noinline, used)) void
port_trainer_choose_moves_minimum_begin(struct trainer_move_choice_state *s)
{
	choice_set_hl(&s->registers, 0xcee9); choice_set_de(&s->registers, 0xcfed);
	s->registers.c = 4;
}

/* 0 repeats the four-slot pass, 1 advances a slot, 2 found a new minimum. */
__attribute__((noinline, used)) port_u8
port_trainer_choose_moves_minimum_step(struct trainer_move_choice_state *s)
{
	port_u16 de = (port_u16)(choice_pair(s->registers.d, s->registers.e) + 1);
	port_u16 hl = choice_pair(s->registers.h, s->registers.l);
	s->registers.a = s->fetched_move; choice_set_de(&s->registers, de); choice_and_a(&s->registers);
	if (s->registers.a == 0) return 0;
	choice_dec(&s->registers, &s->fetched_score); s->written = s->fetched_score;
	s->write_h = s->registers.h; s->write_l = s->registers.l;
	if (s->fetched_score == 0) return 2;
	hl++; choice_set_hl(&s->registers, hl); choice_dec(&s->registers, &s->registers.c);
	return s->registers.c == 0 ? 0 : 1;
}

/* Returns 1 to repeat the undo recurrence. */
__attribute__((noinline, used)) port_u8
port_trainer_choose_moves_undo_step(struct trainer_move_choice_state *s)
{
	port_u16 hl = choice_pair(s->registers.h, s->registers.l);
	choice_inc(&s->registers, &s->fetched_score); s->written = s->fetched_score;
	s->write_h = s->registers.h; s->write_l = s->registers.l;
	hl--; choice_set_hl(&s->registers, hl); choice_inc(&s->registers, &s->registers.a);
	choice_cp(&s->registers, 5);
	return (s->registers.f & PORT_FLAG_Z) == 0;
}

__attribute__((noinline, used)) void
port_trainer_choose_moves_filter_begin(struct trainer_move_choice_state *s)
{
	choice_set_hl(&s->registers, 0xcee9); choice_set_de(&s->registers, 0xcfed);
	s->registers.c = 4;
}

/* Returns 1 for another of the four filter slots. */
__attribute__((noinline, used)) port_u8
port_trainer_choose_moves_filter_step(struct trainer_move_choice_state *s)
{
	port_u16 hl = choice_pair(s->registers.h, s->registers.l);
	port_u16 de = choice_pair(s->registers.d, s->registers.e);
	s->registers.a = s->fetched_move; choice_and_a(&s->registers);
	if (s->registers.a == 0) s->written = s->registers.a;
	s->registers.a = s->fetched_score; choice_dec(&s->registers, &s->registers.a);
	if (s->registers.a == 0) s->registers.a = s->fetched_move;
	else { s->registers.a = 0; s->registers.f = PORT_FLAG_Z; }
	s->written = s->registers.a; s->write_h = s->registers.h; s->write_l = s->registers.l;
	hl++; de++; choice_set_hl(&s->registers, hl); choice_set_de(&s->registers, de);
	choice_dec(&s->registers, &s->registers.c);
	return s->registers.c != 0;
}

__attribute__((noinline, used)) void
port_trainer_choose_moves_finish(struct trainer_move_choice_state *s)
{
	choice_set_hl(&s->registers, 0xcee9);
}

static void
trainer_mod_setup(struct trainer_ai_mod_state *s)
{
	choice_set_hl(&s->registers, 0xcee8); choice_set_de(&s->registers, 0xcfed);
	s->registers.b = 5;
}

static void
trainer_mod_inc_hl(struct cpu_register_state *r)
{
	choice_set_hl(r, (port_u16)(choice_pair(r->h, r->l) + 1));
}

static void
trainer_mod_inc_de(struct cpu_register_state *r)
{
	choice_set_de(r, (port_u16)(choice_pair(r->d, r->e) + 1));
}

/* Shared one-slot recurrence used by all three modification routines. */
__attribute__((noinline, used)) port_u8
port_ai_move_choice_modification_next_move(struct trainer_ai_mod_state *s)
{
	choice_dec(&s->registers, &s->registers.b);
	if (s->registers.f & PORT_FLAG_Z) return 0;
	trainer_mod_inc_hl(&s->registers);
	s->registers.a = s->move; choice_and_a(&s->registers);
	if (s->registers.f & PORT_FLAG_Z) return 0;
	trainer_mod_inc_de(&s->registers);
	s->read_move_called = 1; return 1;
}

/* Returns 0 when finished and 1 when the first move is ready for ReadMove. */
__attribute__((noinline, used)) port_u8
port_ai_move_choice_modification1_begin(struct trainer_ai_mod_state *s)
{
	s->registers.a = s->battle_mon_status; choice_and_a(&s->registers);
	if (s->registers.f & PORT_FLAG_Z) return 0;
	trainer_mod_setup(s); choice_dec(&s->registers, &s->registers.b);
	trainer_mod_inc_hl(&s->registers);
	s->registers.a = s->move; choice_and_a(&s->registers);
	if (s->registers.f & PORT_FLAG_Z) return 0;
	trainer_mod_inc_de(&s->registers); s->read_move_called = 1; return 1;
}

/* Returns 1 when a status-only move was discouraged. */
__attribute__((noinline, used)) port_u8
port_ai_move_choice_modification1_score(struct trainer_ai_mod_state *s)
{
	static const port_u8 effects[4] = { 0x01, 0x20, 0x42, 0x43 };
	port_u8 i;
	s->registers.a = s->move_power; choice_and_a(&s->registers);
	if ((s->registers.f & PORT_FLAG_Z) == 0) return 0;
	s->registers.a = s->move_effect;
	for (i = 0; i != 4; i++) if (s->registers.a == effects[i]) {
		s->registers.a = s->score; choice_add_immediate(&s->registers, 5);
		s->written = s->registers.a; s->write_h = s->registers.h; s->write_l = s->registers.l;
		return 1;
	}
	/* IsInArray reaches its $ff terminator and executes AND A. */
	s->registers.a = 0xff; choice_and_a(&s->registers);
	return 0;
}

__attribute__((noinline, used)) port_u8
port_ai_move_choice_modification2_begin(struct trainer_ai_mod_state *s)
{
	s->registers.a = s->layer2_encouragement; choice_cp(&s->registers, 1);
	if ((s->registers.f & PORT_FLAG_Z) == 0) return 0;
	trainer_mod_setup(s); return 1;
}

/* Returns 1 and decrements the score for one of the preferred effect bands. */
__attribute__((noinline, used)) port_u8
port_ai_move_choice_modification2_score(struct trainer_ai_mod_state *s)
{
	port_u8 e = s->move_effect;
	s->registers.a = e; choice_cp(&s->registers, 0x0a); if (s->registers.f & PORT_FLAG_C) return 0;
	choice_cp(&s->registers, 0x1a); if (s->registers.f & PORT_FLAG_C) goto prefer;
	choice_cp(&s->registers, 0x32); if (s->registers.f & PORT_FLAG_C) return 0;
	choice_cp(&s->registers, 0x42); if ((s->registers.f & PORT_FLAG_C) == 0) return 0;
prefer:
	choice_dec_memory(&s->registers, s->score, &s->written);
	s->write_h = s->registers.h; s->write_l = s->registers.l; return 1;
}

/* 0=neutral, 1=encouraged, 2=needs better-move scan. */
__attribute__((noinline, used)) port_u8
port_ai_move_choice_modification3_effectiveness(struct trainer_ai_mod_state *s)
{
	s->registers.a = s->type_effectiveness; choice_cp(&s->registers, 0x10);
	if (s->registers.f & PORT_FLAG_Z) return 0;
	if (s->registers.f & PORT_FLAG_C) return 2;
	choice_dec_memory(&s->registers, s->score, &s->written);
	s->write_h = s->registers.h; s->write_l = s->registers.l; return 1;
}

__attribute__((noinline, used)) void
port_ai_move_choice_modification3_scan_begin(struct trainer_ai_mod_state *s)
{
	s->registers.a = s->enemy_move_type; s->registers.d = s->registers.a;
	choice_set_hl(&s->registers, 0xcfed); s->registers.b = 5; s->registers.c = 0;
}

/* 0=scan done without a better move, 1=continue, 2=better move found. */
__attribute__((noinline, used)) port_u8
port_ai_move_choice_modification3_scan_step(struct trainer_ai_mod_state *s)
{
	struct cpu_register_state *r = &s->registers;
	choice_dec(r, &r->b);
	if (r->f & PORT_FLAG_Z) goto done;
	r->a = s->move; trainer_mod_inc_hl(r); choice_and_a(r);
	if (r->f & PORT_FLAG_Z) goto done;
	s->read_move_called = 1;
	r->a = s->move_effect; choice_cp(r, 0x28); if (r->f & PORT_FLAG_Z) goto found;
	choice_cp(r, 0x29); if (r->f & PORT_FLAG_Z) goto found;
	choice_cp(r, 0x2b); if (r->f & PORT_FLAG_Z) goto found;
	r->a = s->enemy_move_type; choice_cp(r, r->d);
	if (r->f & PORT_FLAG_Z) return 1;
	r->a = s->move_power; choice_and_a(r);
	if (r->f & PORT_FLAG_Z) return 1;
found:
	r->c = r->a; return 2;
done:
	r->a = r->c; return 0;
}

__attribute__((noinline, used)) port_u8
port_ai_move_choice_modification3_scan_finish(struct trainer_ai_mod_state *s)
{
	choice_and_a(&s->registers);
	if (s->registers.f & PORT_FLAG_Z) return 0;
	{
		port_u8 value;
		choice_inc(&s->registers, &s->score); value = s->score;
		s->written = value; s->write_h = s->registers.h; s->write_l = s->registers.l;
	}
	return 1;
}

__attribute__((noinline, used)) void
port_ai_move_choice_modification1(struct trainer_ai_mod_state *s)
{
	static const port_u8 status_effects[4] = { 0x01, 0x20, 0x42, 0x43 };
	port_u8 slot, i;
	s->registers.a = s->battle_mon_status; choice_and_a(&s->registers);
	if (s->registers.f & PORT_FLAG_Z) return;
	trainer_mod_setup(s);
	for (slot = 0; slot != 4; slot++) {
		choice_dec(&s->registers, &s->registers.b);
		trainer_mod_inc_hl(&s->registers);
		s->registers.a = s->moves[slot]; choice_and_a(&s->registers);
		if (s->registers.f & PORT_FLAG_Z) return;
		trainer_mod_inc_de(&s->registers); s->read_move_called = 1;
		s->registers.a = s->move_powers[slot]; choice_and_a(&s->registers);
		if ((s->registers.f & PORT_FLAG_Z) == 0) continue;
		s->registers.a = s->move_effects[slot];
		for (i = 0; i != 4; i++) {
			if (s->registers.a != status_effects[i]) continue;
			s->registers.a = s->scores[slot]; choice_add_immediate(&s->registers, 5);
			s->scores[slot] = s->registers.a; s->written = s->registers.a;
			s->write_h = s->registers.h; s->write_l = s->registers.l;
			break;
		}
		if (i == 4) {
			s->registers.a = 0xff; choice_and_a(&s->registers);
		}
	}
	choice_dec(&s->registers, &s->registers.b);
}

__attribute__((noinline, used)) void
port_ai_move_choice_modification2(struct trainer_ai_mod_state *s)
{
	port_u8 slot;
	s->registers.a = s->layer2_encouragement; choice_cp(&s->registers, 1);
	if ((s->registers.f & PORT_FLAG_Z) == 0) return;
	trainer_mod_setup(s);
	for (slot = 0; slot != 4; slot++) {
		choice_dec(&s->registers, &s->registers.b);
		trainer_mod_inc_hl(&s->registers);
		s->registers.a = s->moves[slot]; choice_and_a(&s->registers);
		if (s->registers.f & PORT_FLAG_Z) return;
		trainer_mod_inc_de(&s->registers); s->read_move_called = 1;
		s->registers.a = s->move_effects[slot];
		choice_cp(&s->registers, 0x0a); if (s->registers.f & PORT_FLAG_C) continue;
		choice_cp(&s->registers, 0x1a); if (s->registers.f & PORT_FLAG_C) goto prefer;
		choice_cp(&s->registers, 0x32); if (s->registers.f & PORT_FLAG_C) continue;
		choice_cp(&s->registers, 0x42); if ((s->registers.f & PORT_FLAG_C) == 0) continue;
prefer:
		choice_dec_memory(&s->registers, s->scores[slot], &s->scores[slot]);
		s->written = s->scores[slot]; s->write_h = s->registers.h; s->write_l = s->registers.l;
	}
	choice_dec(&s->registers, &s->registers.b);
}

__attribute__((noinline, used)) void
port_ai_move_choice_modification3(struct trainer_ai_mod_state *s)
{
	port_u8 slot, candidate;
	trainer_mod_setup(s);
	for (slot = 0; slot != 4; slot++) {
		choice_dec(&s->registers, &s->registers.b);
		trainer_mod_inc_hl(&s->registers);
		s->registers.a = s->moves[slot]; choice_and_a(&s->registers);
		if (s->registers.f & PORT_FLAG_Z) return;
		trainer_mod_inc_de(&s->registers); s->read_move_called = 1; s->effectiveness_called = 1;
		s->registers.a = s->type_effectivenesses[slot]; choice_cp(&s->registers, 0x10);
		if (s->registers.f & PORT_FLAG_Z) continue;
		if ((s->registers.f & PORT_FLAG_C) == 0) {
			choice_dec_memory(&s->registers, s->scores[slot], &s->scores[slot]);
			s->written = s->scores[slot]; s->write_h = s->registers.h; s->write_l = s->registers.l;
			continue;
		}
		{
			port_u8 better = 0;
			for (candidate = 0; candidate != 4; candidate++) {
				port_u8 effect;
				s->registers.a = s->moves[candidate]; choice_and_a(&s->registers);
				if (s->registers.f & PORT_FLAG_Z) break;
				s->read_move_called = 1; effect = s->move_effects[candidate];
				if (effect == 0x28 || effect == 0x29 || effect == 0x2b) { better = effect; break; }
				if (s->move_types[candidate] != s->move_types[slot] && s->move_powers[candidate] != 0) {
					better = s->move_powers[candidate]; break;
				}
			}
			s->registers.a = better; choice_and_a(&s->registers);
			if (s->registers.f & PORT_FLAG_Z) continue;
			choice_inc(&s->registers, &s->scores[slot]);
			s->written = s->scores[slot]; s->write_h = s->registers.h; s->write_l = s->registers.l;
		}
	}
	choice_dec(&s->registers, &s->registers.b);
}

static void
trainer_copy_to_mod(struct trainer_ai_mod_state *m, struct trainer_move_choice_state *s)
{
	port_u8 i;
	m->registers = s->registers;
	m->battle_mon_status = s->battle_mon_status;
	m->layer2_encouragement = s->layer2_encouragement;
	for (i = 0; i != 4; i++) {
		m->moves[i] = s->enemy_moves[i]; m->move_powers[i] = s->move_powers[i];
		m->move_effects[i] = s->move_effects[i]; m->move_types[i] = s->move_types[i];
		m->type_effectivenesses[i] = s->type_effectivenesses[i]; m->scores[i] = s->buffer[i];
	}
	m->read_move_called = s->read_move_called;
	m->effectiveness_called = s->effectiveness_called;
}

static void
trainer_copy_from_mod(struct trainer_move_choice_state *s, struct trainer_ai_mod_state *m)
{
	port_u8 i;
	s->registers = m->registers;
	for (i = 0; i != 4; i++) s->buffer[i] = m->scores[i];
	s->written = m->written; s->write_h = m->write_h; s->write_l = m->write_l;
	s->read_move_called = m->read_move_called;
	s->effectiveness_called = m->effectiveness_called;
}

__attribute__((noinline, used)) void
port_ai_enemy_trainer_choose_moves(struct trainer_move_choice_state *s)
{
	struct trainer_ai_mod_state modification = {0};
	port_u16 table_pointer;
	port_u8 offset, id, i, step;
	port_trainer_choose_moves_init(s);
	port_trainer_choose_moves_class_begin(s);
	table_pointer = choice_pair(s->registers.h, s->registers.l);
	offset = (port_u8)(table_pointer - 0x589b);
	/* A zero first entry selects the original move array immediately. */
	id = move_choice_table[offset]; s->registers.a = id; choice_and_a(&s->registers);
	if (id == 0) {
		choice_set_hl(&s->registers, 0xcfed);
		return;
	}
	for (;;) {
		id = move_choice_table[offset++]; s->modification = id;
		if (!port_trainer_choose_moves_modification(s)) break;
		trainer_copy_to_mod(&modification, s);
		if (id == 1) port_ai_move_choice_modification1(&modification);
		else if (id == 2) port_ai_move_choice_modification2(&modification);
		else if (id == 3) port_ai_move_choice_modification3(&modification);
		trainer_copy_from_mod(s, &modification);
		s->registers.h = s->saved_h; s->registers.l = s->saved_l;
	}

	port_trainer_choose_moves_minimum_begin(s);
	for (;;) {
		for (i = 0; i != 4; i++) {
			s->fetched_move = s->enemy_moves[i]; s->fetched_score = s->buffer[i];
			step = port_trainer_choose_moves_minimum_step(s);
			if (s->enemy_moves[i] != 0) s->buffer[i] = s->fetched_score;
			if (step == 2) goto found_minimum;
			if (step == 0) break;
		}
		port_trainer_choose_moves_minimum_begin(s);
	}

found_minimum:
	s->registers.a = s->registers.c;
	for (;;) {
		s->fetched_score = s->buffer[i]; step = port_trainer_choose_moves_undo_step(s);
		s->buffer[i] = s->fetched_score;
		if (!step) break;
		i--;
	}

	port_trainer_choose_moves_filter_begin(s);
	for (i = 0; i != 4; i++) {
		s->fetched_move = s->enemy_moves[i]; s->fetched_score = s->buffer[i];
		(void)port_trainer_choose_moves_filter_step(s); s->buffer[i] = s->written;
	}
	port_trainer_choose_moves_finish(s);
}
