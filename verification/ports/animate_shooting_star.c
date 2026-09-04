#include "port_state.h"

void port_load_shooting_star_graphics(struct cpu_register_state *, port_u8 *);
void port_play_sound(struct play_sound_state *);
void port_check_for_user_interruption(struct cpu_register_state *, port_u8 *);
void port_move_down_small_stars(struct cpu_register_state *, port_u8 *);
void port_copy_data(struct cpu_register_state *, port_u8 *);

#define W_SHADOW_OAM 0xc300u
#define W_SHADOW_OAM_SPRITE04 (W_SHADOW_OAM + 4u * 4u)
#define W_SHADOW_OAM_SPRITE20 (W_SHADOW_OAM + 20u * 4u)
#define W_SHADOW_OAM_SPRITE23 (W_SHADOW_OAM + 23u * 4u)
#define W_MOVE_DOWN_SMALL_STARS_OAM_COUNT 0xcd3du
#define R_OBP0 0xff48u
#define R_OBP1 0xff49u
#define W_NEW_SOUND_ID 0xc0eeu
#define W_AUDIO_ROM_BANK 0xc0efu
#define W_AUDIO_SAVED_ROM_BANK 0xc0f0u
#define W_FADE_CONTROL 0xcfc7u
#define W_FADE_RELOAD 0xcfc8u
#define W_FADE_COUNTER 0xcfc9u
#define W_LAST_MUSIC_SOUND_ID 0xcfcau
#define W_CHANNEL_SOUND_IDS 0xc026u
#define SMALL_STARS_WAVE_POINTERS 0x40f4u
#define H_SAVED_ROM_BANK 0xffb9u
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u
#define SMALL_STARS_OAM 0x40eeu
#define SMALL_STARS_WAVE1_COORDS 0x40feu
#define SMALL_STARS_WAVE_SIZE 8u
#define OBJ_SIZE 4u
#define SCREEN_HEIGHT_PX_PLUS_OAM_Y_OFS 0xa0u
#define SFX_SHOOTING_STAR 0xc2u

static void
play_shooting_star_sound(struct cpu_register_state *registers, port_u8 *memory)
{
	struct play_sound_state sound = { 0 };

	sound.registers = *registers;
	sound.registers.a = SFX_SHOOTING_STAR;
	sound.new_sound_id = memory[W_NEW_SOUND_ID];
	sound.audio_rom_bank = memory[W_AUDIO_ROM_BANK];
	sound.fade_control = memory[W_FADE_CONTROL];
	sound.fade_reload = memory[W_FADE_RELOAD];
	sound.fade_counter = memory[W_FADE_COUNTER];
	sound.last_music_sound_id = memory[W_LAST_MUSIC_SOUND_ID];
	for (port_u8 i = 0; i < 4u; ++i)
		sound.channel_sound_ids[i] = memory[W_CHANNEL_SOUND_IDS + i];
	sound.saved_rom_bank = memory[H_SAVED_ROM_BANK];
	sound.loaded_rom_bank = memory[H_LOADED_ROM_BANK];
	sound.rom_bank = memory[R_ROMB];
	sound.audio_saved_rom_bank = memory[W_AUDIO_SAVED_ROM_BANK];
	port_play_sound(&sound);
	*registers = sound.registers;
	memory[W_NEW_SOUND_ID] = sound.new_sound_id;
	memory[W_AUDIO_ROM_BANK] = sound.audio_rom_bank;
	memory[W_AUDIO_SAVED_ROM_BANK] = sound.audio_saved_rom_bank;
	memory[W_FADE_CONTROL] = sound.fade_control;
	memory[W_FADE_RELOAD] = sound.fade_reload;
	memory[W_FADE_COUNTER] = sound.fade_counter;
	memory[W_LAST_MUSIC_SOUND_ID] = sound.last_music_sound_id;
	for (port_u8 i = 0; i < 4u; ++i)
		memory[W_CHANNEL_SOUND_IDS + i] = sound.channel_sound_ids[i];
	memory[H_SAVED_ROM_BANK] = sound.saved_rom_bank;
	memory[H_LOADED_ROM_BANK] = sound.loaded_rom_bank;
	memory[R_ROMB] = sound.rom_bank;
}

static void
copy_data(struct cpu_register_state *registers, port_u8 *memory,
	port_u16 source, port_u16 destination, port_u16 size)
{
	registers->h = (port_u8)(source >> 8);
	registers->l = (port_u8)source;
	registers->d = (port_u8)(destination >> 8);
	registers->e = (port_u8)destination;
	registers->b = (port_u8)(size >> 8);
	registers->c = (port_u8)size;
	port_copy_data(registers, memory);
}

static void
check_interruption(struct cpu_register_state *registers, port_u8 *memory,
	port_u8 count)
{
	registers->c = count;
	port_check_for_user_interruption(registers, memory);
}

/* Port of AnimateShootingStar in engine/movie/splash.asm. */
__attribute__((noinline, used)) void
port_animate_shooting_star(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u8 wave_count = 6u;
	port_u16 table_cursor = SMALL_STARS_WAVE_POINTERS;

	port_load_shooting_star_graphics(registers, memory);
	play_shooting_star_sound(registers, memory);

	registers->h = (port_u8)(W_SHADOW_OAM >> 8);
	registers->l = (port_u8)W_SHADOW_OAM;
	registers->b = 0xa0u;
	registers->c = 4u;
	for (;;) {
		port_u16 cursor = W_SHADOW_OAM;
		port_u8 saved_b = registers->b;
		port_u8 saved_c = registers->c;

		for (port_u8 i = 0; i < 4u; ++i) {
			memory[cursor] = (port_u8)(memory[cursor] + 4u);
			++cursor;
			memory[cursor] = (port_u8)(memory[cursor] - 4u);
			cursor += 3u;
		}
		check_interruption(registers, memory, 1u);
		registers->b = saved_b;
		registers->c = saved_c;
		if ((registers->f & PORT_FLAG_C) != 0)
			return;
		port_u8 y = memory[W_SHADOW_OAM];
		if (y == 0x80u || y != registers->b)
			continue;
		break;
	}

	registers->h = (port_u8)((W_SHADOW_OAM + 4u * OBJ_SIZE) >> 8);
	registers->l = (port_u8)(W_SHADOW_OAM + 4u * OBJ_SIZE);
	registers->d = 0;
	registers->e = OBJ_SIZE;
	registers->c = 0;
	for (port_u8 i = 0; i < 4u; ++i) {
		memory[W_SHADOW_OAM + i * OBJ_SIZE] =
			SCREEN_HEIGHT_PX_PLUS_OAM_Y_OFS;
		registers->h = (port_u8)((W_SHADOW_OAM + (i + 1u) * OBJ_SIZE) >> 8);
		registers->l = (port_u8)(W_SHADOW_OAM + (i + 1u) * OBJ_SIZE);
		registers->f = (port_u8)(PORT_FLAG_N |
			(i == 3u ? PORT_FLAG_Z : 0));
	}

	registers->b = 3u;
	registers->h = (port_u8)(R_OBP0 >> 8);
	registers->l = (port_u8)R_OBP0;
	for (;;) {
		port_u8 value = memory[R_OBP0];
		memory[R_OBP0] = (port_u8)((value >> 1) | (value << 7));
		registers->f = (port_u8)((memory[R_OBP0] == 0 ? PORT_FLAG_Z : 0) |
			((value & 1u) != 0 ? PORT_FLAG_C : 0));
		value = memory[R_OBP0];
		memory[R_OBP0] = (port_u8)((value >> 1) | (value << 7));
		registers->f = (port_u8)((memory[R_OBP0] == 0 ? PORT_FLAG_Z : 0) |
			((value & 1u) != 0 ? PORT_FLAG_C : 0));
		check_interruption(registers, memory, 10u);
		if ((registers->f & PORT_FLAG_C) != 0)
			return;
		--registers->b;
		if (registers->b == 0)
			break;
	}

	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	registers->d = (port_u8)(W_SHADOW_OAM >> 8);
	registers->e = (port_u8)W_SHADOW_OAM;
	for (port_u8 i = 0; i < 24u; ++i)
		copy_data(registers, memory, SMALL_STARS_OAM, W_SHADOW_OAM, 4u);

	memory[W_MOVE_DOWN_SMALL_STARS_OAM_COUNT] = 0;
	registers->h = (port_u8)(SMALL_STARS_WAVE_POINTERS >> 8);
	registers->l = (port_u8)SMALL_STARS_WAVE_POINTERS;
	registers->c = wave_count;
	for (port_u8 i = 0; i < wave_count; ++i) {
		port_u16 source = (port_u16)memory[table_cursor] |
			((port_u16)memory[table_cursor + 1u] << 8);
		port_u8 saved_b = registers->b;
		port_u8 saved_c = registers->c;
		port_u16 saved_hl = (port_u16)(table_cursor + 2u);
		table_cursor = saved_hl;
		registers->d = (port_u8)(source >> 8);
		registers->e = (port_u8)source;
		for (port_u8 star = 0; star < 4u; ++star) {
			port_u8 y = memory[source];
			if (y == 0xffu)
				break;
			memory[W_SHADOW_OAM_SPRITE20 + star * OBJ_SIZE] = y;
			++source;
			memory[W_SHADOW_OAM_SPRITE20 + star * OBJ_SIZE + 1u] =
				memory[source];
			source += 5u;
		}
		if (memory[W_MOVE_DOWN_SMALL_STARS_OAM_COUNT] != 24u)
			memory[W_MOVE_DOWN_SMALL_STARS_OAM_COUNT] += 6u;
		port_move_down_small_stars(registers, memory);
		port_u8 saved_a = registers->a;
		port_u8 saved_f = registers->f;
		copy_data(registers, memory, W_SHADOW_OAM_SPRITE04, W_SHADOW_OAM,
			OBJ_SIZE * 20u);
		registers->a = saved_a;
		registers->f = saved_f;
		registers->h = (port_u8)(saved_hl >> 8);
		registers->l = (port_u8)saved_hl;
		registers->b = saved_b;
		registers->c = saved_c;
		if ((saved_f & PORT_FLAG_C) != 0)
			return;
		--registers->c;
	}
	registers->a = 0;
	registers->f = PORT_FLAG_Z;
}
