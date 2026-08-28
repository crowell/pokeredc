#include "port_state.h"

#define W_STATUS_FLAGS5 0xd730u
#define W_PLAYER_DIRECTION 0xd52au
#define W_PLAYER_COLLISION 0xc10cu
#define W_TILE_IN_FRONT 0xcfc6u
#define W_CUR_MAP_TILESET 0xd367u
#define W_COLLISION_PTR 0xd530u
#define W_WALK_BIKE_SURF_STATE 0xd700u
#define W_CHANNEL_SOUND_IDS 0xc026u
#define W_LAST_MUSIC_SOUND_ID 0xcfcau
#define W_STATUS_FLAGS4 0xd72eu
#define W_LOW_HEALTH_ALARM 0xd083u
#define W_AUDIO_ROM_BANK 0xc0efu
#define W_AUDIO_SAVED_ROM_BANK 0xc0f0u
#define W_NEW_SOUND_ID 0xc0eeu
#define W_FADE_CONTROL 0xcfc7u
#define W_FADE_RELOAD 0xcfc8u
#define W_FADE_COUNTER 0xcfc9u
#define W_SAVED_ROM_BANK 0xffb9u
#define W_LOADED_ROM_BANK 0xffb8u
#define W_ROM_BANK 0x2000u
#define SHIP_PORT 0x0eu
#define SFX_COLLISION 0xb4u
#define PORT_FLAG_C 0x10u
#define PORT_FLAG_Z 0x80u

void port_check_for_jumping_and_tile_pair_collisions(struct cpu_register_state *,
	port_u8 *);
void port_get_tile_and_coords_in_front(struct cpu_register_state *, port_u8 *);
void port_load_player_sprite_graphics(struct cpu_register_state *, port_u8 *);
void port_play_default_music(struct default_music_fade_state *,
	const struct cpu_register_state *, const port_u8[2]);
void port_play_sound(struct play_sound_state *);

static void
and_a(struct cpu_register_state *r)
{
	r->f = r->a == 0u ? PORT_FLAG_Z : 0u;
}

static void
play_collision_sound(struct cpu_register_state *r, port_u8 *memory)
{
	struct play_sound_state sound = {0};

	sound.registers = *r;
	sound.registers.a = SFX_COLLISION;
	sound.new_sound_id = memory[W_NEW_SOUND_ID];
	sound.audio_rom_bank = memory[W_AUDIO_ROM_BANK];
	sound.fade_control = memory[W_FADE_CONTROL];
	sound.fade_reload = memory[W_FADE_RELOAD];
	sound.fade_counter = memory[W_FADE_COUNTER];
	sound.last_music_sound_id = memory[W_LAST_MUSIC_SOUND_ID];
	for (port_u8 i = 0; i < 4u; ++i)
		sound.channel_sound_ids[i] = memory[W_CHANNEL_SOUND_IDS + i];
	sound.saved_rom_bank = memory[W_SAVED_ROM_BANK];
	sound.loaded_rom_bank = memory[W_LOADED_ROM_BANK];
	sound.rom_bank = memory[W_ROM_BANK];
	sound.low_health_alarm = memory[W_LOW_HEALTH_ALARM];
	sound.audio_saved_rom_bank = memory[W_AUDIO_SAVED_ROM_BANK];
	port_play_sound(&sound);
	*r = sound.registers;
	memory[W_NEW_SOUND_ID] = sound.new_sound_id;
	memory[W_AUDIO_ROM_BANK] = sound.audio_rom_bank;
	memory[W_AUDIO_SAVED_ROM_BANK] = sound.audio_saved_rom_bank;
	memory[W_FADE_CONTROL] = sound.fade_control;
	memory[W_FADE_RELOAD] = sound.fade_reload;
	memory[W_FADE_COUNTER] = sound.fade_counter;
	memory[W_LAST_MUSIC_SOUND_ID] = sound.last_music_sound_id;
	for (port_u8 i = 0; i < 4u; ++i)
		memory[W_CHANNEL_SOUND_IDS + i] = sound.channel_sound_ids[i];
	memory[W_SAVED_ROM_BANK] = sound.saved_rom_bank;
	memory[W_LOADED_ROM_BANK] = sound.loaded_rom_bank;
	memory[W_ROM_BANK] = sound.rom_bank;
	memory[W_LOW_HEALTH_ALARM] = sound.low_health_alarm;
}

static void
stop_surfing(struct cpu_register_state *r, port_u8 *memory)
{
	struct default_music_fade_state music = {0};
	struct cpu_register_state callback_registers;
	port_u8 callback_globals[2] = {
		memory[W_STATUS_FLAGS4], memory[W_LAST_MUSIC_SOUND_ID]
	};

	r->a = 0u;
	r->f = PORT_FLAG_Z;
	memory[W_WALK_BIKE_SURF_STATE] = 0u;
	port_load_player_sprite_graphics(r, memory);
	callback_registers = *r;
	music.registers = *r;
	music.status_flags4 = memory[W_STATUS_FLAGS4];
	music.last_music_sound_id = memory[W_LAST_MUSIC_SOUND_ID];
	music.low_health_alarm = memory[W_LOW_HEALTH_ALARM];
	for (port_u8 i = 0; i < 3u; ++i)
		music.channel_sound_ids[i] = memory[W_CHANNEL_SOUND_IDS + i];
	port_play_default_music(&music, &callback_registers, callback_globals);
	*r = music.registers;
	memory[W_STATUS_FLAGS4] = music.status_flags4;
	memory[W_LAST_MUSIC_SOUND_ID] = music.last_music_sound_id;
	memory[W_LOW_HEALTH_ALARM] = music.low_health_alarm;
	for (port_u8 i = 0; i < 3u; ++i)
		memory[W_CHANNEL_SOUND_IDS + i] = music.channel_sound_ids[i];
	and_a(r);
}

static void
collision(struct cpu_register_state *r, port_u8 *memory)
{
	r->a = memory[W_CHANNEL_SOUND_IDS + 4u];
	r->f = r->a == SFX_COLLISION ? PORT_FLAG_Z : 0u;
	if (r->a != SFX_COLLISION)
		play_collision_sound(r, memory);
	r->f = (port_u8)((r->f & PORT_FLAG_Z) | PORT_FLAG_C);
}

/* Port of CollisionCheckOnWater in home/overworld.asm. */
__attribute__((noinline, used)) void
port_collision_check_on_water(struct cpu_register_state *r, port_u8 *memory)
{
	r->a = memory[W_STATUS_FLAGS5];
	if ((r->a & (1u << 7)) != 0u) {
		and_a(r);
		return;
	}
	r->d = memory[W_PLAYER_DIRECTION];
	r->a = memory[W_PLAYER_COLLISION];
	r->a &= r->d;
	and_a(r);
	if (r->a == 0u) {
		r->h = 0x0cu;
		r->l = 0x8au;
		port_check_for_jumping_and_tile_pair_collisions(r, memory);
		if ((r->f & PORT_FLAG_C) != 0u) {
			collision(r, memory);
			return;
		}
		port_get_tile_and_coords_in_front(r, memory);
		r->a = memory[W_TILE_IN_FRONT];
		if (r->a == 0x14u || r->a == 0x48u) {
			and_a(r);
			return;
		}
		if (r->a == 0x32u && memory[W_CUR_MAP_TILESET] != SHIP_PORT) {
			and_a(r);
			return;
		}
	}

	port_u16 pointer = (port_u16)(memory[W_COLLISION_PTR] |
		((port_u16)memory[W_COLLISION_PTR + 1u] << 8));
	for (;;) {
		port_u8 value = memory[pointer++];
		r->a = value;
		r->l = (port_u8)pointer;
		r->h = (port_u8)(pointer >> 8);
		if (value == 0xffu) {
			collision(r, memory);
			return;
		}
		if (value == r->c) {
			stop_surfing(r, memory);
			return;
		}
	}
}
