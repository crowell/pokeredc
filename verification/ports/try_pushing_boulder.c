#include "port_state.h"

#define H_SPRITE_INDEX 0xff8cu
#define H_JOY_HELD 0xffb4u
#define W_MISC_FLAGS 0xcd60u
#define W_STATUS_FLAGS1 0xd728u
#define W_BOULDER_INDEX 0xd718u
#define W_MOVEMENT_STATUS 0xc101u
#define W_FACING 0xc109u
#define W_TILE_BOULDER_RESULT 0xd71cu
#define W_NUM_SPRITES 0xd4e1u
#define W_CHANNEL_SOUND_IDS 0xc026u
#define W_NEW_SOUND_ID 0xc0eeu
#define W_AUDIO_ROM_BANK 0xc0efu
#define W_AUDIO_SAVED_ROM_BANK 0xc0f0u
#define W_FADE_CONTROL 0xcfc7u
#define W_FADE_RELOAD 0xcfc8u
#define W_FADE_COUNTER 0xcfc9u
#define W_LAST_MUSIC_SOUND_ID 0xcfcau
#define W_SAVED_ROM_BANK 0xffb9u
#define W_LOADED_ROM_BANK 0xffb8u
#define W_ROM_BANK 0x2000u
#define W_LOW_HEALTH_ALARM 0xd083u
#define SFX_PUSH_BOULDER 0xa8u
#define PAD_CTRL_PAD 0xf0u
#define BOULDER_MOVEMENT_BYTE_2 0x10u

void port_is_sprite_in_front_of_player(struct cpu_register_state *);
void port_is_sprite_in_front_of_player2(struct sprite_in_front_state *, port_u8 *);
void port_get_sprite_movement_byte2_pointer(struct memory_predicate_state *);
void port_check_for_collision_when_pushing_boulder(struct cpu_register_state *, port_u8 *);
void port_move_sprite(struct cpu_register_state *, port_u8 *);
void port_reset_boulder_push_flags(struct misc_flags_state *);
void port_play_sound(struct play_sound_state *);

static void
bit_memory(struct cpu_register_state *r, port_u8 value, unsigned bit)
{
	port_u8 flags = (port_u8)(r->f & PORT_FLAG_C);
	flags |= PORT_FLAG_H;
	if ((value & (port_u8)(1u << bit)) == 0)
		flags |= PORT_FLAG_Z;
	r->f = flags;
}

static void
cp_immediate(struct cpu_register_state *r, port_u8 value)
{
	port_u8 left = r->a;
	port_u8 result = (port_u8)(left - value);

	r->f = PORT_FLAG_N;
	if (result == 0)
		r->f |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (value & 0x0fu))
		r->f |= PORT_FLAG_H;
	if (left < value)
		r->f |= PORT_FLAG_C;
}

static void
reset_flags(struct cpu_register_state *r, port_u8 *memory)
{
	struct misc_flags_state state = {0};

	state.registers = *r;
	state.misc_flags = memory[W_MISC_FLAGS];
	port_reset_boulder_push_flags(&state);
	*r = state.registers;
	memory[W_MISC_FLAGS] = state.misc_flags;
}

static void
find_boulder(struct cpu_register_state *r, port_u8 *memory)
{
	struct sprite_in_front_state state = {0};

	state.registers = *r;
	state.facing_direction = memory[W_FACING];
	state.num_sprites = memory[W_NUM_SPRITES];
	port_is_sprite_in_front_of_player(&state.registers);
	port_is_sprite_in_front_of_player2(&state, memory);
	*r = state.registers;
	memory[H_SPRITE_INDEX] = state.text_id;
}

static port_u16
movement_byte2_pointer(struct cpu_register_state *r, port_u8 *memory)
{
	struct memory_predicate_state state = {0};
	port_u16 pointer;

	state.registers = *r;
	state.value = memory[H_SPRITE_INDEX];
	port_get_sprite_movement_byte2_pointer(&state);
	*r = state.registers;
	pointer = (port_u16)(((port_u16)r->h << 8) | r->l);
	return pointer;
}

static void
play_push_sound(struct cpu_register_state *r, port_u8 *memory)
{
	struct play_sound_state sound = {0};

	sound.registers = *r;
	sound.registers.a = SFX_PUSH_BOULDER;
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
move_boulder(struct cpu_register_state *r, port_u8 *memory, port_u16 data)
{
	/* The four movement tables are immutable ROM bytes in the original. */
	memory[data] = (port_u8)(data == 0x72adu ? 0x40u :
		data == 0x72afu ? 0x00u : data == 0x72b1u ? 0x80u : 0xc0u);
	memory[(port_u16)(data + 1u)] = 0xffu;
	r->d = (port_u8)(data >> 8);
	r->e = (port_u8)data;
	port_move_sprite(r, memory);
}

/* Port of TryPushingBoulder in engine/overworld/push_boulder.asm. */
__attribute__((noinline, used)) void
port_try_pushing_boulder(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 sprite;
	port_u8 held;
	port_u16 pointer;

	r->a = memory[W_STATUS_FLAGS1];
	bit_memory(r, r->a, 0);
	if ((r->f & PORT_FLAG_Z) != 0)
		return;
	r->a = memory[W_MISC_FLAGS];
	bit_memory(r, r->a, 1);
	if ((r->f & PORT_FLAG_Z) == 0)
		return;
	r->a = 0;
	r->f = PORT_FLAG_Z;
	memory[H_SPRITE_INDEX] = 0;
	find_boulder(r, memory);
	sprite = memory[H_SPRITE_INDEX];
	memory[W_BOULDER_INDEX] = sprite;
	r->a = sprite;
	if (sprite == 0) {
		reset_flags(r, memory);
		return;
	}
	r->h = 0xc1;
	r->l = (port_u8)(0x01u + ((port_u8)((sprite << 4) | (sprite >> 4))));
	memory[(port_u16)(((port_u16)r->h << 8) | r->l)] &= 0x7fu;
	pointer = movement_byte2_pointer(r, memory);
	r->a = memory[pointer];
	cp_immediate(r, BOULDER_MOVEMENT_BYTE_2);
	if ((r->f & PORT_FLAG_Z) == 0) {
		reset_flags(r, memory);
		return;
	}
	{
		port_u8 old = memory[W_MISC_FLAGS];
		bit_memory(r, old, 6);
		memory[W_MISC_FLAGS] = (port_u8)(old | 0x40u);
		if ((r->f & PORT_FLAG_Z) != 0)
			return;
	}
	held = memory[H_JOY_HELD];
	r->a = held;
	r->a &= PAD_CTRL_PAD;
	r->f = r->a == 0 ? PORT_FLAG_Z : 0;
	if ((r->f & PORT_FLAG_Z) != 0)
		return;
	port_check_for_collision_when_pushing_boulder(r, memory);
	r->a = memory[W_TILE_BOULDER_RESULT];
	if (r->a != 0) {
		reset_flags(r, memory);
		return;
	}
	r->b = held;
	r->a = memory[W_FACING];
	cp_immediate(r, 4);
	if ((r->f & PORT_FLAG_Z) != 0) {
		if ((held & 0x04u) == 0) {
			r->f = (port_u8)((r->f & PORT_FLAG_C) | PORT_FLAG_H | PORT_FLAG_Z);
			return;
		}
		move_boulder(r, memory, 0x72adu);
	} else {
		cp_immediate(r, 8);
		if ((r->f & PORT_FLAG_Z) != 0) {
			if ((held & 0x02u) == 0)
				return;
			move_boulder(r, memory, 0x72b1u);
		} else {
			cp_immediate(r, 12);
			if ((r->f & PORT_FLAG_Z) != 0) {
				if ((held & 0x01u) == 0)
					return;
				move_boulder(r, memory, 0x72b3u);
			} else {
				if ((held & 0x08u) == 0)
					return;
				move_boulder(r, memory, 0x72afu);
			}
		}
	}
	play_push_sound(r, memory);
	memory[W_MISC_FLAGS] |= 0x02u;
}
