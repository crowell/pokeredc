#include "joypad_port.h"

#define W_DEX_RATING_NUM_MONS_SEEN 0xcc5bu
#define W_NUM_SET_BITS 0xd11eu
#define W_POKEDEX_OWNED 0xd2f7u
#define W_POKEDEX_SEEN 0xd30au
#define W_EVENT_FLAGS 0xd747u
#define H_DEX_RATING_NUM_MONS_SEEN 0xffdbu
#define H_DEX_RATING_NUM_MONS_OWNED 0xffdcu
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u
#define POKEDEX_BYTES 19u
#define DEX_COMPLETION_TEXT 0x41ccu
#define PLAY_POKEDEX_RATING_SFX 0x513bu
#define PLAY_POKEDEX_RATING_SFX_BANK 0x1fu
#define EVENT_HALL_OF_FAME_DEX_RATING_MASK 0x08u

struct play_pokedex_rating_sfx_state {
	struct cpu_register_state registers;
	port_u8 num_mons_owned;
	port_u8 new_sound_id;
	port_u8 audio_fade_out_control;
	port_u8 audio_rom_bank;
	port_u8 audio_saved_bank;
	port_u8 last_music_sound_id;
	port_u8 stop_sound_called;
	port_u8 rating_sound_called;
	port_u8 default_music_called;
};

struct display_dex_rating_private_state {
	struct cpu_register_state registers;
	port_u8 new_sound_id;
	port_u8 audio_fade_out_control;
	port_u8 audio_rom_bank;
	port_u8 audio_saved_bank;
	port_u8 last_music_sound_id;
	port_u8 stop_sound_called;
	port_u8 rating_sound_called;
	port_u8 default_music_called;
	port_u8 wait_joy5;
	port_u8 wait_down_arrow_blink1;
	port_u8 wait_down_arrow_blink2;
	port_u8 wait_b;
	port_u8 wait_c;
	port_u8 wait_d;
	port_u8 wait_e;
	port_u8 wait_h;
	port_u8 wait_l;
};

void port_count_set_bits(struct bit_count_state *, const port_u8 *);
void port_print_text(struct cpu_register_state *, port_u8 *);
void port_play_pokedex_rating_sfx(struct play_pokedex_rating_sfx_state *);

static void count_bitmap(struct cpu_register_state *registers, port_u8 *memory,
	port_u16 address)
{
	struct bit_count_state count = {0};

	count.registers = *registers;
	count.registers.h = (port_u8)(address >> 8);
	count.registers.l = (port_u8)address;
	count.registers.b = POKEDEX_BYTES;
	count.num_set_bits = memory[W_NUM_SET_BITS];
	port_count_set_bits(&count, memory);
	*registers = count.registers;
	memory[W_NUM_SET_BITS] = count.num_set_bits;
}

static void compare_a_b(struct cpu_register_state *registers)
{
	port_u8 a = registers->a;
	port_u8 b = registers->b;
	port_u8 result = (port_u8)(a - b);

	registers->f = PORT_FLAG_N;
	if (result == 0u)
		registers->f |= PORT_FLAG_Z;
	if ((a & 0x0fu) < (b & 0x0fu))
		registers->f |= PORT_FLAG_H;
	if (a < b)
		registers->f |= PORT_FLAG_C;
}

/* Complete port of DisplayDexRating in engine/events/pokedex_rating.asm. */
__attribute__((noinline, used)) void
port_display_dex_rating_private(struct display_dex_rating_private_state *state,
	port_u8 *memory)
{
	static const port_u8 limits[16] = {
		10, 20, 30, 40, 50, 60, 70, 80,
		90, 100, 110, 120, 130, 140, 150, 152
	};
	static const port_u16 texts[16] = {
		0x4201, 0x4206, 0x420b, 0x4210,
		0x4215, 0x421a, 0x421f, 0x4224,
		0x4229, 0x422e, 0x4233, 0x4238,
		0x423d, 0x4242, 0x4247, 0x424c
	};
	port_u8 index = 0;
	port_u16 text;

	count_bitmap(&state->registers, memory, W_POKEDEX_SEEN);
	state->registers.a = memory[W_NUM_SET_BITS];
	memory[H_DEX_RATING_NUM_MONS_SEEN] = state->registers.a;
	count_bitmap(&state->registers, memory, W_POKEDEX_OWNED);
	state->registers.a = memory[W_NUM_SET_BITS];
	memory[H_DEX_RATING_NUM_MONS_OWNED] = state->registers.a;

	for (;;) {
		state->registers.b = limits[index];
		state->registers.a = memory[H_DEX_RATING_NUM_MONS_OWNED];
		compare_a_b(&state->registers);
		if (state->registers.a < state->registers.b)
			break;
		index++;
	}
	text = texts[index];
	state->registers.a = (port_u8)text;
	state->registers.h = (port_u8)(text >> 8);
	state->registers.l = state->registers.a;

	state->registers.a = memory[W_EVENT_FLAGS];
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_H;
	if (!(state->registers.a & EVENT_HALL_OF_FAME_DEX_RATING_MASK))
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a &= (port_u8)~EVENT_HALL_OF_FAME_DEX_RATING_MASK;
	memory[W_EVENT_FLAGS] = state->registers.a;

	if (!(state->registers.f & PORT_FLAG_Z)) {
		port_u16 de = W_DEX_RATING_NUM_MONS_SEEN;
		port_u16 hl = text;

		state->registers.d = (port_u8)(de >> 8);
		state->registers.e = (port_u8)de;
		state->registers.a = memory[H_DEX_RATING_NUM_MONS_SEEN];
		memory[de++] = state->registers.a;
		state->registers.d = (port_u8)(de >> 8);
		state->registers.e = (port_u8)de;
		state->registers.a = memory[H_DEX_RATING_NUM_MONS_OWNED];
		memory[de++] = state->registers.a;
		for (;;) {
			state->registers.a = memory[hl++];
			state->registers.h = (port_u8)(hl >> 8);
			state->registers.l = (port_u8)hl;
			state->registers.f = PORT_FLAG_N;
			if (state->registers.a == 0x50u)
				state->registers.f |= PORT_FLAG_Z;
			if (state->registers.a == 0x50u) {
				memory[de] = state->registers.a;
				break;
			}
			memory[de++] = state->registers.a;
			state->registers.d = (port_u8)(de >> 8);
			state->registers.e = (port_u8)de;
		}
		return;
	}

	{
		port_u8 selected_h = state->registers.h;
		port_u8 selected_l = state->registers.l;
		struct play_pokedex_rating_sfx_state sfx = {0};
		struct wait_for_text_scroll_state wait = {0};
		port_u8 saved_bank;
		port_u8 saved_f;

		state->registers.h = (port_u8)(DEX_COMPLETION_TEXT >> 8);
		state->registers.l = (port_u8)DEX_COMPLETION_TEXT;
		port_print_text(&state->registers, memory);
		state->registers.h = selected_h;
		state->registers.l = selected_l;
		port_print_text(&state->registers, memory);

		/* farcall PlayPokedexRatingSfx, including Bankswitch's ABI. */
		state->registers.b = PLAY_POKEDEX_RATING_SFX_BANK;
		state->registers.h = (port_u8)(PLAY_POKEDEX_RATING_SFX >> 8);
		state->registers.l = (port_u8)PLAY_POKEDEX_RATING_SFX;
		saved_bank = memory[H_LOADED_ROM_BANK];
		saved_f = state->registers.f;
		memory[H_LOADED_ROM_BANK] = PLAY_POKEDEX_RATING_SFX_BANK;
		memory[R_ROMB] = PLAY_POKEDEX_RATING_SFX_BANK;
		state->registers.b = 0x35;
		state->registers.c = 0xe4;
		sfx.registers = state->registers;
		sfx.num_mons_owned = memory[H_DEX_RATING_NUM_MONS_OWNED];
		sfx.new_sound_id = state->new_sound_id;
		sfx.audio_fade_out_control = state->audio_fade_out_control;
		sfx.audio_rom_bank = state->audio_rom_bank;
		sfx.audio_saved_bank = state->audio_saved_bank;
		sfx.last_music_sound_id = state->last_music_sound_id;
		sfx.stop_sound_called = state->stop_sound_called;
		sfx.rating_sound_called = state->rating_sound_called;
		sfx.default_music_called = state->default_music_called;
		port_play_pokedex_rating_sfx(&sfx);
		state->registers = sfx.registers;
		state->new_sound_id = sfx.new_sound_id;
		state->audio_fade_out_control = sfx.audio_fade_out_control;
		state->audio_rom_bank = sfx.audio_rom_bank;
		state->audio_saved_bank = sfx.audio_saved_bank;
		state->last_music_sound_id = sfx.last_music_sound_id;
		state->stop_sound_called = sfx.stop_sound_called;
		state->rating_sound_called = sfx.rating_sound_called;
		state->default_music_called = sfx.default_music_called;
		state->registers.b = saved_bank;
		state->registers.c = saved_f;
		state->registers.a = saved_bank;
		memory[H_LOADED_ROM_BANK] = saved_bank;
		memory[R_ROMB] = saved_bank;

		wait.registers = state->registers;
		wait.joy5 = state->wait_joy5;
		wait.down_arrow_blink1 = state->wait_down_arrow_blink1;
		wait.down_arrow_blink2 = state->wait_down_arrow_blink2;
		wait.wait_b = state->wait_b;
		wait.wait_c = state->wait_c;
		wait.wait_d = state->wait_d;
		wait.wait_e = state->wait_e;
		wait.wait_h = state->wait_h;
		wait.wait_l = state->wait_l;
		port_wait_for_text_scroll_button_press(&wait);
		state->registers = wait.registers;
		state->wait_down_arrow_blink1 = wait.down_arrow_blink1;
		state->wait_down_arrow_blink2 = wait.down_arrow_blink2;
	}
}
