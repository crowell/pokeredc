#include "port_state.h"

#define W_MOVEMENT_FLAGS 0xd736u
#define W_SIMULATED_INDEX 0xcd38u
#define W_PLAYER_DIRECTION 0xd52au
#define W_PLAYER_COLLISION 0xc10cu
#define W_NUM_SPRITES 0xd4e1u
#define W_FACING 0xc109u
#define H_TEXT_ID 0xff8cu
#define W_CHANNEL_SOUND_IDS 0xc026u
#define SFX_COLLISION 0xb4u
#define PORT_FLAG_C 0x10u
#define PORT_FLAG_H 0x20u
#define PORT_FLAG_Z 0x80u

void port_is_sprite_in_front_of_player2(struct sprite_in_front_state *, port_u8 *);
void port_check_for_jumping_and_tile_pair_collisions(struct cpu_register_state *, port_u8 *);
void port_check_tile_passable(struct cpu_register_state *, port_u8 *);
void port_play_sound(struct play_sound_state *);

static void
and_a(struct cpu_register_state *r)
{
	r->f = (port_u8)(r->a == 0u ? PORT_FLAG_Z : 0u);
}

static void
set_scf(struct cpu_register_state *r)
{
	r->f = (port_u8)((r->f & PORT_FLAG_Z) | PORT_FLAG_C);
}

static void
update_sprite_front(struct cpu_register_state *r, port_u8 *memory)
{
	struct sprite_in_front_state state = {0};

	state.registers = *r;
	state.facing_direction = memory[W_FACING];
	state.num_sprites = memory[W_NUM_SPRITES];
	state.registers.d = 0x10u;
	port_is_sprite_in_front_of_player2(&state, memory);
	*r = state.registers;
	memory[W_PLAYER_DIRECTION] = state.player_direction;
	memory[H_TEXT_ID] = state.text_id;
}

static void
play_collision_sound(struct cpu_register_state *r, port_u8 *memory)
{
	struct play_sound_state sound = {0};

	sound.registers = *r;
	sound.registers.a = SFX_COLLISION;
	sound.new_sound_id = memory[0xc0eeu];
	sound.audio_rom_bank = memory[0xc0efu];
	sound.fade_control = memory[0xcfc7u];
	sound.fade_reload = memory[0xcfc8u];
	sound.fade_counter = memory[0xcfc9u];
	sound.last_music_sound_id = memory[0xcfcau];
	for (port_u8 i = 0; i < 4u; ++i)
		sound.channel_sound_ids[i] = memory[W_CHANNEL_SOUND_IDS + i];
	sound.saved_rom_bank = memory[0xffb9u];
	sound.loaded_rom_bank = memory[0xffb8u];
	sound.rom_bank = memory[0x2000u];
	sound.low_health_alarm = memory[0xd083u];
	sound.audio_saved_rom_bank = memory[0xc0f0u];
	port_play_sound(&sound);
	*r = sound.registers;
	memory[0xc0eeu] = sound.new_sound_id;
	memory[0xc0efu] = sound.audio_rom_bank;
	memory[0xc0f0u] = sound.audio_saved_rom_bank;
	memory[0xcfc7u] = sound.fade_control;
	memory[0xcfc8u] = sound.fade_reload;
	memory[0xcfc9u] = sound.fade_counter;
	memory[0xcfcau] = sound.last_music_sound_id;
	for (port_u8 i = 0; i < 4u; ++i)
		memory[W_CHANNEL_SOUND_IDS + i] = sound.channel_sound_ids[i];
	memory[0xffb9u] = sound.saved_rom_bank;
	memory[0xffb8u] = sound.loaded_rom_bank;
	memory[0x2000u] = sound.rom_bank;
	memory[0xd083u] = sound.low_health_alarm;
}

/* Port of CollisionCheckOnLand in home/overworld.asm. */
__attribute__((noinline, used)) void
port_collision_check_on_land(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 movement = memory[W_MOVEMENT_FLAGS];

	r->a = movement;
	if ((movement & 0x40u) != 0u)
		goto no_collision;
	r->a = memory[W_SIMULATED_INDEX];
	and_a(r);
	if (memory[W_SIMULATED_INDEX] != 0u)
		goto no_collision;
	r->d = memory[W_PLAYER_DIRECTION];
	r->a = memory[W_PLAYER_COLLISION];
	r->a &= r->d;
	and_a(r);
	if (r->a != 0u)
		goto collision;
	memory[H_TEXT_ID] = 0u;
	update_sprite_front(r, memory);
	r->a = memory[H_TEXT_ID];
	and_a(r);
	if (r->a != 0u)
		goto collision;
	r->h = 0x0cu;
	r->l = 0x7eu;
	port_check_for_jumping_and_tile_pair_collisions(r, memory);
	if ((r->f & PORT_FLAG_C) != 0u)
		goto collision;
	port_check_tile_passable(r, memory);
	if ((r->f & PORT_FLAG_C) == 0u)
		goto no_collision;

collision:
	r->a = memory[W_CHANNEL_SOUND_IDS + 4u];
	r->f = r->a == SFX_COLLISION ? PORT_FLAG_Z : 0u;
	if (r->a != SFX_COLLISION)
		play_collision_sound(r, memory);
	set_scf(r);
	return;

no_collision:
	and_a(r);
}
