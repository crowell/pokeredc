#include "port_state.h"
#ifdef PORT_PLATFORM_RUNTIME
#include "bank.h"
#endif

#define W_TEXT_CONTROL 0xcc3cu
#define W_PREDEF_ID 0xcc4eu
#define W_PREDEF_HL 0xcc4fu
#define W_PREDEF_DE 0xcc51u
#define W_PREDEF_BC 0xcc53u
#define W_PREDEF_PARENT_BANK 0xcf12u
#define W_PREDEF_BANK 0xd0b7u
#define W_NUM_SET_BITS 0xd11eu
#define W_POKEDEX_OWNED 0xd2f7u
#define W_OAKS_LAB_CUR_SCRIPT 0xd5f0u
#define W_STATUS_FLAGS4 0xd72eu
#define W_PALLET_EVENT_FLAGS 0xd747u
#define W_OAKS_LAB_EVENT_FLAGS 0xd74bu
#define W_ROUTE22_EVENT_FLAGS 0xd7ebu
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u

#define EVENT_PALLET_AFTER_GETTING_POKEBALLS 0x40u
#define EVENT_GOT_POKEDEX 0x20u
#define EVENT_GOT_POKEBALLS_FROM_OAK 0x10u
#define EVENT_BATTLED_RIVAL_IN_OAKS_LAB 0x08u
#define EVENT_BEAT_ROUTE22_RIVAL_1ST_BATTLE 0x20u
#define BIT_GOT_STARTER 0x08u
#define POKE_BALL 0x04u
#define OAKS_PARCEL 0x46u
#define POKEDEX_BYTES 19u
#define SCRIPT_RIVAL_ARRIVES 0x0fu

struct display_dex_rating_private_state {
	struct cpu_register_state registers;
	port_u8 new_sound_id, audio_fade_out_control, audio_rom_bank;
	port_u8 audio_saved_bank, last_music_sound_id, stop_sound_called;
	port_u8 rating_sound_called, default_music_called, wait_joy5;
	port_u8 wait_down_arrow_blink1, wait_down_arrow_blink2;
	port_u8 wait_b, wait_c, wait_d, wait_e, wait_h, wait_l;
};

void port_count_set_bits(struct bit_count_state *, const port_u8 *);
void port_is_item_in_bag(struct cpu_register_state *, port_u8 *);
void port_give_item(struct cpu_register_state *, port_u8 *);
void port_print_text(struct cpu_register_state *, port_u8 *);
void port_display_dex_rating_private(struct display_dex_rating_private_state *,
	port_u8 *);
void port_oaks_lab_script_remove_parcel(struct cpu_register_state *, port_u8 *);
void port_text_script_end(struct cpu_register_state *);

static port_u8 test_bit(struct cpu_register_state *r, port_u8 value,
	port_u8 mask)
{
	r->a = value;
	r->f = (port_u8)((r->f & PORT_FLAG_C) | PORT_FLAG_H);
	if (!(value & mask))
		r->f |= PORT_FLAG_Z;
	return (port_u8)(value & mask);
}

static void print_selected(struct oaks_lab_oak1_text_state *state,
	port_u8 *memory, port_u16 text)
{
	state->selected_text_low = (port_u8)text;
	state->selected_text_high = (port_u8)(text >> 8);
	state->registers.h = state->selected_text_high;
	state->registers.l = state->selected_text_low;
	port_print_text(&state->registers, memory);
}

static void finish(struct oaks_lab_oak1_text_state *state)
{
	port_text_script_end(&state->registers);
}

/* Complete executable callback behind OaksLabOak1Text's text_asm marker. */
__attribute__((noinline, used)) void
port_oaks_lab_oak1_text(struct oaks_lab_oak1_text_state *state,
	port_u8 *memory)
{
	if (test_bit(&state->registers, memory[W_PALLET_EVENT_FLAGS],
		EVENT_PALLET_AFTER_GETTING_POKEBALLS))
		goto already_got_poke_balls;
	{
		struct bit_count_state count = {0};
		count.registers = state->registers;
		count.registers.h = (port_u8)(W_POKEDEX_OWNED >> 8);
		count.registers.l = (port_u8)W_POKEDEX_OWNED;
		count.registers.b = POKEDEX_BYTES;
		count.num_set_bits = memory[W_NUM_SET_BITS];
		port_count_set_bits(&count, memory);
		state->registers = count.registers;
		memory[W_NUM_SET_BITS] = count.num_set_bits;
	}
	state->registers.a = memory[W_NUM_SET_BITS];
	{
		port_u8 a = state->registers.a;
		state->registers.f = PORT_FLAG_N;
		if (a == 2u) state->registers.f |= PORT_FLAG_Z;
		if ((a & 0x0fu) < 2u) state->registers.f |= PORT_FLAG_H;
		if (a < 2u) state->registers.f |= PORT_FLAG_C;
	}
	if (state->registers.f & PORT_FLAG_C)
		goto check_for_poke_balls;
	if (!test_bit(&state->registers, memory[W_OAKS_LAB_EVENT_FLAGS],
		EVENT_GOT_POKEDEX))
		goto check_for_poke_balls;

already_got_poke_balls:
	print_selected(state, memory, 0x531du);
	state->registers.a = 1;
	memory[W_TEXT_CONTROL] = state->registers.a;
	{
		struct display_dex_rating_private_state dex = {0};
		port_u8 saved_bank = memory[H_LOADED_ROM_BANK];
		port_u8 saved_f = state->registers.f;
		state->registers.a = 0x56u;
		memory[W_PREDEF_ID] = state->registers.a;
		memory[W_PREDEF_PARENT_BANK] = saved_bank;
		memory[W_PREDEF_HL] = state->registers.h;
		memory[W_PREDEF_HL + 1u] = state->registers.l;
		memory[W_PREDEF_DE] = state->registers.d;
		memory[W_PREDEF_DE + 1u] = state->registers.e;
		memory[W_PREDEF_BC] = state->registers.b;
		memory[W_PREDEF_BC + 1u] = state->registers.c;
		memory[W_PREDEF_BANK] = 0x11u;
		memory[H_LOADED_ROM_BANK] = 0x11u;
		memory[R_ROMB] = 0x11u;
#ifdef PORT_PLATFORM_RUNTIME
		port_sync_rom_window(memory, 0x11u);
#endif
		dex.registers = state->registers;
		dex.new_sound_id = state->new_sound_id;
		dex.audio_fade_out_control = state->audio_fade_out_control;
		dex.audio_rom_bank = state->audio_rom_bank;
		dex.audio_saved_bank = state->audio_saved_bank;
		dex.last_music_sound_id = state->last_music_sound_id;
		dex.stop_sound_called = state->stop_sound_called;
		dex.rating_sound_called = state->rating_sound_called;
		dex.default_music_called = state->default_music_called;
		dex.wait_joy5 = state->wait_joy5;
		dex.wait_down_arrow_blink1 = state->wait_down_arrow_blink1;
		dex.wait_down_arrow_blink2 = state->wait_down_arrow_blink2;
		dex.wait_b = state->wait_b; dex.wait_c = state->wait_c;
		dex.wait_d = state->wait_d; dex.wait_e = state->wait_e;
		dex.wait_h = state->wait_h; dex.wait_l = state->wait_l;
		port_display_dex_rating_private(&dex, memory);
		state->registers = dex.registers;
		state->new_sound_id = dex.new_sound_id;
		state->audio_fade_out_control = dex.audio_fade_out_control;
		state->audio_rom_bank = dex.audio_rom_bank;
		state->audio_saved_bank = dex.audio_saved_bank;
		state->last_music_sound_id = dex.last_music_sound_id;
		state->stop_sound_called = dex.stop_sound_called;
		state->rating_sound_called = dex.rating_sound_called;
		state->default_music_called = dex.default_music_called;
		state->wait_down_arrow_blink1 = dex.wait_down_arrow_blink1;
		state->wait_down_arrow_blink2 = dex.wait_down_arrow_blink2;
		state->registers.a = saved_bank;
		state->registers.f = saved_f;
		memory[H_LOADED_ROM_BANK] = saved_bank;
		memory[R_ROMB] = saved_bank;
#ifdef PORT_PLATFORM_RUNTIME
		port_sync_rom_window(memory, saved_bank);
#endif
	}
	finish(state);
	return;

check_for_poke_balls:
	state->registers.b = POKE_BALL;
	port_is_item_in_bag(&state->registers, memory);
	if (!(state->registers.f & PORT_FLAG_Z))
		goto come_see_me_sometimes;
	if (test_bit(&state->registers, memory[W_ROUTE22_EVENT_FLAGS],
		EVENT_BEAT_ROUTE22_RIVAL_1ST_BATTLE))
		goto give_poke_balls;
	if (test_bit(&state->registers, memory[W_OAKS_LAB_EVENT_FLAGS],
		EVENT_GOT_POKEDEX)) {
		print_selected(state, memory, 0x5309u);
		finish(state); return;
	}
	if (!test_bit(&state->registers, state->registers.a,
		EVENT_BATTLED_RIVAL_IN_OAKS_LAB)) {
		if (test_bit(&state->registers, memory[W_STATUS_FLAGS4], BIT_GOT_STARTER))
			print_selected(state, memory, 0x52f5u);
		else
			print_selected(state, memory, 0x52f0u);
		finish(state); return;
	}
	state->registers.b = OAKS_PARCEL;
	port_is_item_in_bag(&state->registers, memory);
	if (!(state->registers.f & PORT_FLAG_Z)) {
		print_selected(state, memory, 0x52ffu);
		port_oaks_lab_script_remove_parcel(&state->registers, memory);
		state->registers.a = SCRIPT_RIVAL_ARRIVES;
		memory[W_OAKS_LAB_CUR_SCRIPT] = state->registers.a;
	} else {
		print_selected(state, memory, 0x52fau);
	}
	finish(state); return;

give_poke_balls:
	state->registers.h = (port_u8)(W_OAKS_LAB_EVENT_FLAGS >> 8);
	state->registers.l = (port_u8)W_OAKS_LAB_EVENT_FLAGS;
	{
		port_u8 prior = memory[W_OAKS_LAB_EVENT_FLAGS];
		port_u8 was_set = (port_u8)(prior &
			EVENT_GOT_POKEBALLS_FROM_OAK);
		state->registers.f = (port_u8)((state->registers.f & PORT_FLAG_C) |
			PORT_FLAG_H | (was_set ? 0u : PORT_FLAG_Z));
		memory[W_OAKS_LAB_EVENT_FLAGS] =
			(port_u8)(prior | EVENT_GOT_POKEBALLS_FROM_OAK);
		if (was_set)
			goto come_see_me_sometimes;
	}
	state->registers.b = POKE_BALL;
	state->registers.c = 5;
	port_give_item(&state->registers, memory);
	print_selected(state, memory, 0x530eu);
	finish(state); return;

come_see_me_sometimes:
	print_selected(state, memory, 0x5318u);
	finish(state);
}
