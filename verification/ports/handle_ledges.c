#include "port_state.h"

#define W_MOVEMENT_FLAGS 0xd736u
#define W_CUR_MAP_TILESET 0xd367u
#define W_FACING 0xc109u
#define W_TILE_IN_FRONT 0xcfc6u
#define W_TILEMAP 0xc3a0u
#define W_JOY_IGNORE 0xcd6bu
#define W_SIMULATED_END 0xccd3u
#define W_SIMULATED_INDEX 0xcd38u
#define W_STATUS_FLAGS5 0xd730u
#define W_OVERRIDE_SIMULATED 0xccd0u
#define W_MOVEMENT_BYTE1 0xc230u
#define H_JOY_HELD 0xffb4u
#define H_LOADED_ROM_BANK 0xffb8u
#define H_SAVED_ROM_BANK 0xffb9u
#define R_ROMB 0x2000u
#define W_NEW_SOUND_ID 0xc0eeu
#define W_AUDIO_ROM_BANK 0xc0efu
#define W_AUDIO_SAVED_ROM_BANK 0xc0f0u
#define W_CHANNEL_SOUND_IDS 0xc026u
#define W_AUDIO_FADE_OUT_CONTROL 0xcfc7u
#define W_AUDIO_FADE_RELOAD 0xcfc8u
#define W_AUDIO_FADE_COUNTER 0xcfc9u
#define W_LAST_MUSIC_SOUND_ID 0xcfca
#define W_LOW_HEALTH_ALARM 0xd083u
#define BIT_LEDGE_OR_FISHING 6u
#define BIT_SCRIPTED_MOVEMENT_STATE 7u
#define BIT_C 0x10u
#define BIT_H 0x20u
#define BIT_N 0x40u
#define BIT_Z 0x80u
#define PAD_BUTTONS 0x0fu
#define PAD_CTRL_PAD 0xf0u
#define SFX_LEDGE 0xa2u

void port_get_tile_and_coords_in_front(struct cpu_register_state *, port_u8 *);
void port_start_simulating_joypad_states(struct zero_stores_state *);
void port_load_hopping_shadow_oam(struct cpu_register_state *, port_u8 *);
void port_play_sound(struct play_sound_state *);

struct ledge_entry {
	port_u8 direction;
	port_u8 standing;
	port_u8 front;
	port_u8 input;
};

static const struct ledge_entry ledges[] = {
	{ 0x00u, 0x2cu, 0x37u, 0x80u },
	{ 0x00u, 0x39u, 0x36u, 0x80u },
	{ 0x00u, 0x39u, 0x37u, 0x80u },
	{ 0x08u, 0x2cu, 0x27u, 0x20u },
	{ 0x08u, 0x39u, 0x27u, 0x20u },
	{ 0x0cu, 0x2cu, 0x0du, 0x10u },
	{ 0x0cu, 0x2cu, 0x1du, 0x10u },
	{ 0x0cu, 0x39u, 0x0du, 0x10u },
};

static void
bit_test(struct cpu_register_state *registers, port_u8 value, port_u8 bit)
{
	registers->f = (port_u8)(registers->f & BIT_C) | BIT_H;
	if ((value & (port_u8)(1u << bit)) == 0)
		registers->f |= BIT_Z;
}

static void
and_a(struct cpu_register_state *registers)
{
	registers->f = registers->a == 0 ? BIT_Z : 0;
}

static void
cp_a(struct cpu_register_state *registers, port_u8 value)
{
	port_u8 left = registers->a;
	port_u8 result = (port_u8)(left - value);

	registers->f = BIT_N;
	if (result == 0)
		registers->f |= BIT_Z;
	if ((left & 0x0fu) < (value & 0x0fu))
		registers->f |= BIT_H;
	if (left < value)
		registers->f |= BIT_C;
}

static void
start_simulation(struct cpu_register_state *registers, port_u8 *memory)
{
	struct zero_stores_state state;

	state.registers = *registers;
	state.memory[0] = memory[W_OVERRIDE_SIMULATED];
	state.memory[1] = memory[W_MOVEMENT_BYTE1];
	state.memory[2] = memory[W_STATUS_FLAGS5];
	port_start_simulating_joypad_states(&state);
	*registers = state.registers;
	memory[W_OVERRIDE_SIMULATED] = state.memory[0];
	memory[W_MOVEMENT_BYTE1] = state.memory[1];
	memory[W_STATUS_FLAGS5] = state.memory[2];
}

static void
play_ledge_sound(struct cpu_register_state *registers, port_u8 *memory)
{
	struct play_sound_state sound = {0};

	sound.registers = *registers;
	sound.new_sound_id = memory[W_NEW_SOUND_ID];
	sound.audio_rom_bank = memory[W_AUDIO_ROM_BANK];
	sound.fade_control = memory[W_AUDIO_FADE_OUT_CONTROL];
	sound.fade_reload = memory[W_AUDIO_FADE_RELOAD];
	sound.fade_counter = memory[W_AUDIO_FADE_COUNTER];
	sound.last_music_sound_id = memory[W_LAST_MUSIC_SOUND_ID];
	for (port_u8 index = 0; index < 4; ++index)
		sound.channel_sound_ids[index] = memory[W_CHANNEL_SOUND_IDS + index];
	sound.saved_rom_bank = memory[H_SAVED_ROM_BANK];
	sound.loaded_rom_bank = memory[H_LOADED_ROM_BANK];
	sound.rom_bank = memory[R_ROMB];
	sound.low_health_alarm = memory[W_LOW_HEALTH_ALARM];
	sound.audio_saved_rom_bank = memory[W_AUDIO_SAVED_ROM_BANK];
	sound.registers.a = SFX_LEDGE;
	port_play_sound(&sound);
	*registers = sound.registers;
	memory[W_NEW_SOUND_ID] = sound.new_sound_id;
	memory[W_AUDIO_ROM_BANK] = sound.audio_rom_bank;
	memory[W_AUDIO_SAVED_ROM_BANK] = sound.audio_saved_rom_bank;
	memory[W_AUDIO_FADE_OUT_CONTROL] = sound.fade_control;
	memory[W_AUDIO_FADE_RELOAD] = sound.fade_reload;
	memory[W_AUDIO_FADE_COUNTER] = sound.fade_counter;
	memory[W_LAST_MUSIC_SOUND_ID] = sound.last_music_sound_id;
	for (port_u8 index = 0; index < 4; ++index)
		memory[W_CHANNEL_SOUND_IDS + index] = sound.channel_sound_ids[index];
	memory[H_SAVED_ROM_BANK] = sound.saved_rom_bank;
	memory[H_LOADED_ROM_BANK] = sound.loaded_rom_bank;
	memory[R_ROMB] = sound.rom_bank;
	memory[W_LOW_HEALTH_ALARM] = sound.low_health_alarm;
}

/* Port of HandleLedges in engine/overworld/ledges.asm. */
__attribute__((noinline, used)) void
port_handle_ledges(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u8 movement = memory[W_MOVEMENT_FLAGS];
	port_u8 facing;
	port_u8 standing;
	port_u8 front;
	port_u8 joy;

	registers->a = movement;
	bit_test(registers, movement, BIT_LEDGE_OR_FISHING);
	if ((movement & (1u << BIT_LEDGE_OR_FISHING)) != 0)
		return;

	registers->a = memory[W_CUR_MAP_TILESET];
	and_a(registers);
	if (registers->a != 0)
		return;

	port_get_tile_and_coords_in_front(registers, memory);
	facing = memory[W_FACING];
	registers->a = facing;
	registers->b = facing;
	standing = memory[W_TILEMAP + 9u * 20u + 8u];
	registers->a = standing;
	registers->c = standing;
	front = memory[W_TILE_IN_FRONT];
	registers->a = front;
	registers->d = front;
	registers->h = 0x66u;
	registers->l = 0xcfu;

	for (port_u8 index = 0; index < sizeof(ledges) / sizeof(ledges[0]); ++index) {
		const struct ledge_entry *entry = &ledges[index];
		registers->a = entry->direction;
		registers->h = (port_u8)((0x66cfu + (port_u16)index * 4u + 1u) >> 8);
		registers->l = (port_u8)(0x66cfu + (port_u16)index * 4u + 1u);
		cp_a(registers, registers->b);
		if (entry->direction != registers->b)
			continue;
		registers->a = entry->standing;
		registers->h = (port_u8)((0x66cfu + (port_u16)index * 4u + 2u) >> 8);
		registers->l = (port_u8)(0x66cfu + (port_u16)index * 4u + 2u);
		cp_a(registers, registers->c);
		if (entry->standing != registers->c)
			continue;
		registers->a = entry->front;
		registers->h = (port_u8)((0x66cfu + (port_u16)index * 4u + 3u) >> 8);
		registers->l = (port_u8)(0x66cfu + (port_u16)index * 4u + 3u);
		cp_a(registers, registers->d);
		if (entry->front != registers->d)
			continue;
		registers->a = entry->input;
		registers->e = entry->input;
		joy = memory[H_JOY_HELD];
		registers->a = (port_u8)(joy & registers->e);
		and_a(registers);
		if (registers->a == 0)
			return;
		registers->a = PAD_BUTTONS | PAD_CTRL_PAD;
		memory[W_JOY_IGNORE] = registers->a;
		memory[W_MOVEMENT_FLAGS] |= (port_u8)(1u << BIT_LEDGE_OR_FISHING);
		registers->h = (port_u8)(W_MOVEMENT_FLAGS >> 8);
		registers->l = (port_u8)W_MOVEMENT_FLAGS;
		start_simulation(registers, memory);
		registers->a = registers->e;
		memory[W_SIMULATED_END] = registers->a;
		memory[W_SIMULATED_END + 1u] = registers->a;
		registers->a = 2;
		memory[W_SIMULATED_INDEX] = registers->a;
		port_load_hopping_shadow_oam(registers, memory);
		registers->a = SFX_LEDGE;
		play_ledge_sound(registers, memory);
		return;
	}

	/* The terminating $ff direction is read with HLI. */
	registers->a = 0xffu;
	registers->h = 0x66u;
	registers->l = 0xf0u;
	cp_a(registers, 0xffu);
}
