#include "port_state.h"

static void
evolution_cp(struct cpu_register_state *r, port_u8 right)
{
	port_u8 left = r->a;
	r->f = PORT_FLAG_N;
	if (left == right) r->f |= PORT_FLAG_Z;
	if ((left & 15) < (right & 15)) r->f |= PORT_FLAG_H;
	if (left < right) r->f |= PORT_FLAG_C;
}

static void
evolution_and_a(struct cpu_register_state *r)
{
	r->f = PORT_FLAG_H | (r->a == 0 ? PORT_FLAG_Z : 0);
}

static void
evolution_inc(struct cpu_register_state *r, port_u8 *value)
{
	port_u8 old = *value, carry = r->f & PORT_FLAG_C;
	(*value)++; r->f = carry;
	if (*value == 0) r->f |= PORT_FLAG_Z;
	if ((old & 15) == 15) r->f |= PORT_FLAG_H;
}

static void
evolution_add_hl(struct cpu_register_state *r, port_u16 right)
{
	port_u16 left = (port_u16)(((port_u16)r->h << 8) | r->l);
	unsigned long wide = (unsigned long)left + right;
	port_u8 f = r->f & PORT_FLAG_Z;
	if ((left & 0xfff) + (right & 0xfff) > 0xfff) f |= PORT_FLAG_H;
	if (wide > 0xffff) f |= PORT_FLAG_C;
	left = (port_u16)wide; r->h = (port_u8)(left >> 8); r->l = (port_u8)left; r->f = f;
}

static void
evolution_sub_carry(struct cpu_register_state *r, port_u8 right, port_u8 carry)
{
	port_u8 left = r->a; unsigned sub = (unsigned)right + carry;
	r->a = (port_u8)(left - sub); r->f = PORT_FLAG_N;
	if (r->a == 0) r->f |= PORT_FLAG_Z;
	if ((left & 15) < ((right & 15) + carry)) r->f |= PORT_FLAG_H;
	if ((unsigned)left < sub) r->f |= PORT_FLAG_C;
}

static void
evolution_add_carry(struct cpu_register_state *r, port_u8 right, port_u8 carry)
{
	port_u8 left = r->a; unsigned sum = (unsigned)left + right + carry;
	r->a = (port_u8)sum; r->f = 0;
	if (r->a == 0) r->f |= PORT_FLAG_Z;
	if ((left & 15) + (right & 15) + carry > 15) r->f |= PORT_FLAG_H;
	if (sum > 255) r->f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) void
port_evolution_after_battle_init(struct evolution_after_battle_state *s)
{
	s->registers.a = s->tile_animations;
	s->saved_registers = s->registers;
	s->registers.a = 0; s->registers.f = PORT_FLAG_Z;
	s->evolution_occurred = s->registers.a;
	s->registers.a--; s->registers.f = PORT_FLAG_N | PORT_FLAG_H;
	s->which_pokemon = s->registers.a;
	s->registers.h = 0xd1; s->registers.l = 0x63;
}

/* Returns 0 at the party terminator and 1 for a species entry. */
__attribute__((noinline, used)) port_u8
port_evolution_party_mon_begin(struct evolution_after_battle_state *s)
{
	s->registers.h = 0xcf; s->registers.l = 0x92;
	evolution_inc(&s->registers, &s->which_pokemon);
	s->registers.h = 0xd1; s->registers.l = 0x64;
	s->registers.a = s->party_species; evolution_cp(&s->registers, 0xff);
	if (s->registers.f & PORT_FLAG_Z) return 0;
	s->evo_old_species = s->registers.a;
	return 1;
}

/* First half of evoEntryLoop. 0=next mon, 1=trade, 2=item, 3=level. */
__attribute__((noinline, used)) port_u8
port_evolution_classify_entry(struct evolution_after_battle_state *s)
{
	struct cpu_register_state *r = &s->registers;
	r->a = s->evolution_type;
	{ port_u16 hl = (port_u16)(((port_u16)r->h << 8) | r->l) + 1; r->h = (port_u8)(hl >> 8); r->l = (port_u8)hl; }
	evolution_and_a(r); if (r->f & PORT_FLAG_Z) return 0;
	r->b = r->a; evolution_cp(r, 3); if (r->f & PORT_FLAG_Z) return 1;
	r->a = s->link_state; evolution_cp(r, 2); if (r->f & PORT_FLAG_Z) return 0;
	r->a = r->b; evolution_cp(r, 2); if (r->f & PORT_FLAG_Z) return 2;
	r->a = s->force_evolution; evolution_and_a(r); if ((r->f & PORT_FLAG_Z) == 0) return 0;
	r->a = r->b; evolution_cp(r, 1); return (r->f & PORT_FLAG_Z) ? 3 : 1;
}

/* Requirement checks. 0=next mon, 1=next entry, 2=perform evolution. */
__attribute__((noinline, used)) port_u8
port_evolution_check_requirement(struct evolution_after_battle_state *s, port_u8 kind)
{
	struct cpu_register_state *r = &s->registers;
	if (kind == 1) {
		r->a = s->link_state; evolution_cp(r, 2); if ((r->f & PORT_FLAG_Z) == 0) return 1;
	}
	r->a = kind == 3 ? s->level_requirement : s->requirement;
	{ port_u16 hl = (port_u16)(((port_u16)r->h << 8) | r->l) + 1; r->h = (port_u8)(hl >> 8); r->l = (port_u8)hl; }
	r->b = r->a;
	if (kind == 2) {
		r->a = s->cur_item; evolution_cp(r, r->b); if ((r->f & PORT_FLAG_Z) == 0) return 1;
		r->a = s->level_requirement;
		{ port_u16 hl = (port_u16)(((port_u16)r->h << 8) | r->l) + 1; r->h = (port_u8)(hl >> 8); r->l = (port_u8)hl; }
		r->b = r->a; r->a = s->loaded_mon_level; evolution_cp(r, r->b); return (r->f & PORT_FLAG_C) ? 1 : 2;
	}
	r->a = s->loaded_mon_level; evolution_cp(r, r->b);
	return (r->f & PORT_FLAG_C) ? (kind == 1 ? 0 : 1) : 2;
}

__attribute__((noinline, used)) void
port_evolution_begin_mutation(struct evolution_after_battle_state *s)
{
	struct cpu_register_state *r = &s->registers;
	s->cur_enemy_level = r->a;
	r->a = 1; s->evolution_occurred = r->a;
	s->saved_entry_h = r->h; s->saved_entry_l = r->l;
	r->a = s->fetched_species; s->evo_new_species = r->a;
	r->a = s->which_pokemon;
	r->h = 0xd2; r->l = 0xb5;
}

/* UI setup through the EvolveMon callback. Returns 1 when it was cancelled. */
__attribute__((noinline, used)) port_u8
port_evolution_animation_transition(struct evolution_after_battle_state *s)
{
	struct cpu_register_state *r = &s->registers;
	s->is_evolving_text_called = 1;
	r->c = 50;
	r->a = 0; r->f = PORT_FLAG_Z; s->auto_bg_transfer_enabled = r->a;
	r->h = 0xc3; r->l = 0xa0; r->b = 12; r->c = 20;
	r->a = 1; s->auto_bg_transfer_enabled = r->a;
	r->a = 0xff; s->update_sprites_enabled = r->a;
	s->clear_sprites_called = 1; s->evolve_mon_called = 1;
	r->a = s->evolution_cancelled; evolution_and_a(r);
	if (r->a != 0) r->f = PORT_FLAG_C;
	return r->a != 0;
}

/* CancelledEvolution after EvolveMon restored the outer evolution-entry HL. */
__attribute__((noinline, used)) void
port_evolution_cancelled_transition(struct evolution_after_battle_state *s)
{
	s->stopped_text_called = 1; s->clear_screen_called = 1;
	s->registers.h = s->saved_entry_h; s->registers.l = s->saved_entry_l;
	s->registers.a = s->link_state; evolution_cp(&s->registers, 2);
	if ((s->registers.f & PORT_FLAG_Z) == 0) s->reload_called = 1;
}

/* Straight-line species/name setup after EvolvedText has returned. */
__attribute__((noinline, used)) void
port_evolution_success_species_transition(struct evolution_after_battle_state *s)
{
	struct cpu_register_state *r = &s->registers;
	s->evolved_text_called = 1;
	r->h = s->saved_entry_h; r->l = s->saved_entry_l;
	r->a = s->fetched_species;
	s->cur_species = r->a; s->loaded_mon_species = r->a; s->evo_new_species = r->a;
	r->a = 1; s->name_list_type = r->a;
	r->a = 14; s->predef_bank = r->a;
}

/* CopyData has returned; prepare and invoke the level-up move learner. */
__attribute__((noinline, used)) void
port_evolution_post_copy_transition(struct evolution_after_battle_state *s)
{
	struct cpu_register_state *r = &s->registers;
	r->a = s->cur_species; s->pokedex_num = r->a;
	r->a = 0; r->f = PORT_FLAG_Z; s->mon_data_location = r->a;
	s->learn_move_called = 1;
}

/* LearnMoveFromLevelUp returned and the saved party-struct pointer is restored. */
__attribute__((noinline, used)) void
port_evolution_set_types_transition(struct evolution_after_battle_state *s)
{
	s->registers.h = s->saved_party_struct_h;
	s->registers.l = s->saved_party_struct_l;
	s->registers.a = 0x42;
	s->set_types_called = 1;
}

/* SetPartyMonTypes returned; reload the overworld tiles only when appropriate. */
__attribute__((noinline, used)) void
port_evolution_success_reload_transition(struct evolution_after_battle_state *s)
{
	struct cpu_register_state *r = &s->registers;
	r->a = s->is_in_battle; evolution_and_a(r);
	if ((r->f & PORT_FLAG_Z) == 0) return;
	r->a = s->link_state; evolution_cp(r, 2);
	if ((r->f & PORT_FLAG_Z) == 0) s->reload_called = 1;
}

/* Successful evolution side effects before the HP-preserving stat copy. */
__attribute__((noinline, used)) void
port_evolution_success_transition(struct evolution_after_battle_state *s)
{
	struct cpu_register_state *r = &s->registers;
	port_u8 old_pokedex = s->pokedex_num;
	port_evolution_success_species_transition(s);
	s->into_text_called = 1;
	r->c = 40; s->clear_screen_called = 1; s->rename_called = 1;
	r->a = s->pokedex_num;
	r->a = s->cur_species; s->pokedex_num = r->a;
	r->a = s->pokedex_num; r->a--; r->f = PORT_FLAG_N | (r->a == 0 ? PORT_FLAG_Z : 0) |
		((s->pokedex_num & 15) == 0 ? PORT_FLAG_H : 0);
	r->h = 0x43; r->l = 0xde; r->b = 0; r->c = 28;
	r->d = 0xd0; r->e = 0xb8;
	r->a = s->cur_species; s->mon_h_index = r->a;
	s->pokedex_num = old_pokedex;
	s->calc_stats_called = 1;
	r->a = s->which_pokemon; r->h = 0xd1; r->l = 0x6b; r->b = 0; r->c = 44;
	evolution_add_hl(r, (port_u16)((port_u16)s->which_pokemon * 44));
}

/* Successful evolution tail after CopyData, including Pokedex updates. */
__attribute__((noinline, used)) void
port_evolution_success_finish(struct evolution_after_battle_state *s)
{
	struct cpu_register_state *r = &s->registers;
	r->a = s->cur_species; s->pokedex_num = r->a;
	r->a = 0; r->f = PORT_FLAG_Z; s->mon_data_location = r->a;
	s->learn_move_called = 1; s->set_types_called = 1;
	r->a = s->is_in_battle; evolution_and_a(r);
	if (r->f & PORT_FLAG_Z) {
		r->a = s->link_state; evolution_cp(r, 2);
		if ((r->f & PORT_FLAG_Z) == 0) s->reload_called = 1;
	}
	r->a = s->pokedex_num; r->a--; r->f = PORT_FLAG_N | (r->a == 0 ? PORT_FLAG_Z : 0) |
		((s->pokedex_num & 15) == 0 ? PORT_FLAG_H : 0);
	r->c = r->a; r->b = 1; r->h = 0xd2; r->l = 0xf7; s->owned_flag_called = 1;
	r->h = 0xd3; r->l = 0x0a; s->seen_flag_called = 1;
	r->a = s->loaded_mon_species; s->party_species_write = r->a;
	r->h = s->saved_entry_h; r->l = s->saved_entry_l;
}

__attribute__((noinline, used)) void
port_evolution_next_entry1(struct evolution_after_battle_state *s)
{
	port_u16 hl = (port_u16)(((port_u16)s->registers.h << 8) | s->registers.l);
	hl += 2; s->registers.h = (port_u8)(hl >> 8); s->registers.l = (port_u8)hl;
}

__attribute__((noinline, used)) void
port_evolution_next_entry2(struct evolution_after_battle_state *s)
{
	port_u16 hl = (port_u16)(((port_u16)s->registers.h << 8) | s->registers.l);
	hl++; s->registers.h = (port_u8)(hl >> 8); s->registers.l = (port_u8)hl;
}

__attribute__((noinline, used)) void
port_evolution_adjust_hp(struct evolution_after_battle_state *s)
{
	struct cpu_register_state *r = &s->registers;
	r->b = 0; r->c = 0x22; evolution_add_hl(r, 0x22);
	r->a = s->old_max_hp_high; r->b = r->a;
	{ port_u16 hl = (port_u16)(((port_u16)r->h << 8) | r->l) + 1; r->h = (port_u8)(hl >> 8); r->l = (port_u8)hl; }
	r->c = s->old_max_hp_low;
	r->h = 0xcf; r->l = 0xbb; r->a = s->loaded_max_hp_low; r->l--;
	evolution_sub_carry(r, r->c, 0); r->c = r->a;
	r->a = s->loaded_max_hp_high; evolution_sub_carry(r, r->b, (r->f & PORT_FLAG_C) != 0); r->b = r->a;
	r->h = 0xcf; r->l = 0x9a; r->a = s->loaded_hp_low;
	evolution_add_carry(r, r->c, 0); s->loaded_hp_low = r->a; r->l--;
	r->a = s->loaded_hp_high; evolution_add_carry(r, r->b, (r->f & PORT_FLAG_C) != 0); s->loaded_hp_high = r->a;
	r->l--; r->b = s->saved_copy_b; r->c = s->saved_copy_c;
}

__attribute__((noinline, used)) void
port_evolution_after_battle_done(struct evolution_after_battle_state *s)
{
	s->registers = s->saved_registers;
	s->tile_animations = s->registers.a;
	s->registers.a = s->link_state; evolution_cp(&s->registers, 2);
	if (s->registers.f & PORT_FLAG_Z) return;
	s->registers.a = s->is_in_battle; evolution_and_a(&s->registers);
	if ((s->registers.f & PORT_FLAG_Z) == 0) return;
	s->registers.a = s->evolution_occurred; evolution_and_a(&s->registers);
	if ((s->registers.f & PORT_FLAG_Z) == 0) s->music_called = 1;
}

__attribute__((noinline, used)) void
port_evolution_reload_tileset_tile_patterns(struct evolution_reload_tileset_state *s)
{
	s->registers.a = s->link_state;
	evolution_cp(&s->registers, 2);
	if ((s->registers.f & PORT_FLAG_Z) == 0) s->reload_called = 1;
}

__attribute__((noinline, used)) void
port_rename_evolved_mon_begin(struct rename_evolved_mon_state *s)
{
	s->registers.a = s->cur_species;
	s->saved_a = s->registers.a; s->saved_f = s->registers.f;
	s->registers.a = s->mon_h_index; s->name_list_index = s->registers.a;
	s->get_name_called = 1;
}

__attribute__((noinline, used)) void
port_rename_evolved_mon_after_get_name(struct rename_evolved_mon_state *s)
{
	s->registers.a = s->saved_a; s->registers.f = s->saved_f;
	s->cur_species = s->registers.a;
	s->registers.h = 0xcd; s->registers.l = 0x6d;
	s->registers.d = 0xcf; s->registers.e = 0x11;
}

/* 0=mismatch/return, 1=compare another byte, 2=standard name matched. */
__attribute__((noinline, used)) port_u8
port_rename_evolved_mon_compare_step(struct rename_evolved_mon_state *s)
{
	port_u16 de = (port_u16)(((port_u16)s->registers.d << 8) | s->registers.e) + 1;
	port_u16 hl = (port_u16)(((port_u16)s->registers.h << 8) | s->registers.l) + 1;
	s->registers.a = s->candidate_char;
	s->registers.d = (port_u8)(de >> 8); s->registers.e = (port_u8)de;
	evolution_cp(&s->registers, s->standard_char);
	s->registers.h = (port_u8)(hl >> 8); s->registers.l = (port_u8)hl;
	if ((s->registers.f & PORT_FLAG_Z) == 0) return 0;
	evolution_cp(&s->registers, 0x50);
	return (s->registers.f & PORT_FLAG_Z) ? 2 : 1;
}

__attribute__((noinline, used)) void
port_rename_evolved_mon_copy_begin(struct rename_evolved_mon_state *s)
{
	port_u16 offset = (port_u16)((port_u16)s->which_pokemon * 11);
	port_u16 nickname = (port_u16)(0xd2b5 + offset);
	s->registers.a = s->which_pokemon;
	s->registers.b = 0; s->registers.c = 11;
	s->registers.h = (port_u8)(nickname >> 8); s->registers.l = (port_u8)nickname;
	s->registers.a = s->cur_species; evolution_cp(&s->registers, 0xc4);
	s->registers.a = s->loaded_rom_bank;
	s->get_name_called = 1;
	s->registers.h = 0xcd; s->registers.l = 0x6d;
	s->registers.d = (port_u8)(nickname >> 8); s->registers.e = (port_u8)nickname;
	s->copy_source_h = 0xcd; s->copy_source_l = 0x6d;
	s->copy_destination_h = (port_u8)(nickname >> 8); s->copy_destination_l = (port_u8)nickname;
	s->copy_called = 1;
}

__attribute__((noinline, used)) void
port_rename_evolved_mon(struct rename_evolved_mon_state *s)
{
	port_u8 result, i;
	port_rename_evolved_mon_begin(s);
	port_rename_evolved_mon_after_get_name(s);
	for (i = 0; i != 11; i++) {
		s->candidate_char = s->candidate_name[i];
		s->standard_char = s->old_standard_name[i];
		result = port_rename_evolved_mon_compare_step(s);
		if (result == 0) return;
		if (result == 2) { port_rename_evolved_mon_copy_begin(s); return; }
	}
}
