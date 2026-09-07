#include "port_state.h"

#define W_CHANNEL_SOUND_IDS 0xc026u
#define W_NEW_SOUND_ID 0xc0eeu
#define W_AUDIO_ROM_BANK 0xc0efu
#define W_AUDIO_SAVED_ROM_BANK 0xc0f0u
#define W_MISC_FLAGS 0xcd60u
#define W_JOY_IGNORE 0xcd6bu
#define W_FADE_CONTROL 0xcfc7u
#define W_FADE_RELOAD 0xcfc8u
#define W_FADE_COUNTER 0xcfc9u
#define W_LAST_MUSIC_SOUND_ID 0xcfcau
#define W_LOW_HEALTH_ALARM 0xd083u
#define W_BOULDER_SPRITE_INDEX 0xd718u
#define W_STATUS_FLAGS5 0xd730u
#define H_SPRITE_INDEX 0xff8cu
#define H_JOY_RELEASED 0xffb2u
#define H_JOY_PRESSED 0xffb3u
#define H_JOY_HELD 0xffb4u
#define H_LOADED_ROM_BANK 0xffb8u
#define H_SAVED_ROM_BANK 0xffb9u
#define R_ROMB 0x2000u
#define SFX_CUT 0xacu

void port_animate_boulder_dust(struct cpu_register_state *, port_u8 *);
void port_discard_button_presses(struct discard_buttons_state *);
void port_reset_boulder_push_flags(struct misc_flags_state *);
void port_get_sprite_movement_byte2_pointer(struct memory_predicate_state *);
void port_play_sound(struct play_sound_state *);

static void
bit_zero(struct cpu_register_state *registers, port_u8 value)
{
	registers->f = (port_u8)((registers->f & PORT_FLAG_C) | PORT_FLAG_H);
	if ((value & 1u) == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
animate_farcall(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];
	port_u8 saved_flags = registers->f;

	registers->h = 0x5f;
	registers->l = 0x54;
	registers->b = 0x1e;
	registers->a = registers->b;
	memory[H_LOADED_ROM_BANK] = registers->a;
	memory[R_ROMB] = registers->a;
	registers->b = 0x35;
	registers->c = 0xe4;
	port_animate_boulder_dust(registers, memory);

	/* Bankswitch.Return restores the AF saved at Bankswitch entry into BC. */
	registers->b = saved_bank;
	registers->c = saved_flags;
	registers->a = saved_bank;
	memory[H_LOADED_ROM_BANK] = saved_bank;
	memory[R_ROMB] = saved_bank;
}

static void
discard_buttons(struct cpu_register_state *registers, port_u8 *memory)
{
	struct discard_buttons_state discard = {0};

	discard.registers = *registers;
	discard.joy_held = memory[H_JOY_HELD];
	discard.joy_pressed = memory[H_JOY_PRESSED];
	discard.joy_released = memory[H_JOY_RELEASED];
	port_discard_button_presses(&discard);
	*registers = discard.registers;
	memory[H_JOY_HELD] = discard.joy_held;
	memory[H_JOY_PRESSED] = discard.joy_pressed;
	memory[H_JOY_RELEASED] = discard.joy_released;
}

static void
reset_boulder_flags(struct cpu_register_state *registers, port_u8 *memory)
{
	struct misc_flags_state flags = {0};

	flags.registers = *registers;
	flags.misc_flags = memory[W_MISC_FLAGS];
	port_reset_boulder_push_flags(&flags);
	*registers = flags.registers;
	memory[W_MISC_FLAGS] = flags.misc_flags;
}

static port_u16
movement_byte2_pointer(struct cpu_register_state *registers, port_u8 sprite)
{
	struct memory_predicate_state pointer = {0};

	pointer.registers = *registers;
	pointer.value = sprite;
	port_get_sprite_movement_byte2_pointer(&pointer);
	*registers = pointer.registers;
	return (port_u16)(((port_u16)registers->h << 8) | registers->l);
}

static void
play_cut_sound(struct cpu_register_state *registers, port_u8 *memory)
{
	struct play_sound_state sound = {0};
	port_u8 i;

	sound.registers = *registers;
	sound.new_sound_id = memory[W_NEW_SOUND_ID];
	sound.audio_rom_bank = memory[W_AUDIO_ROM_BANK];
	sound.audio_saved_rom_bank = memory[W_AUDIO_SAVED_ROM_BANK];
	sound.fade_control = memory[W_FADE_CONTROL];
	sound.fade_reload = memory[W_FADE_RELOAD];
	sound.fade_counter = memory[W_FADE_COUNTER];
	sound.last_music_sound_id = memory[W_LAST_MUSIC_SOUND_ID];
	for (i = 0; i < 4u; ++i)
		sound.channel_sound_ids[i] = memory[W_CHANNEL_SOUND_IDS + i];
	sound.saved_rom_bank = memory[H_SAVED_ROM_BANK];
	sound.loaded_rom_bank = memory[H_LOADED_ROM_BANK];
	sound.rom_bank = memory[R_ROMB];
	sound.low_health_alarm = memory[W_LOW_HEALTH_ALARM];
	port_play_sound(&sound);
	*registers = sound.registers;
	memory[W_NEW_SOUND_ID] = sound.new_sound_id;
	memory[W_AUDIO_ROM_BANK] = sound.audio_rom_bank;
	memory[W_AUDIO_SAVED_ROM_BANK] = sound.audio_saved_rom_bank;
	memory[W_FADE_CONTROL] = sound.fade_control;
	memory[W_FADE_RELOAD] = sound.fade_reload;
	memory[W_FADE_COUNTER] = sound.fade_counter;
	memory[W_LAST_MUSIC_SOUND_ID] = sound.last_music_sound_id;
	for (i = 0; i < 4u; ++i)
		memory[W_CHANNEL_SOUND_IDS + i] = sound.channel_sound_ids[i];
	memory[H_SAVED_ROM_BANK] = sound.saved_rom_bank;
	memory[H_LOADED_ROM_BANK] = sound.loaded_rom_bank;
	memory[R_ROMB] = sound.rom_bank;
	memory[W_LOW_HEALTH_ALARM] = sound.low_health_alarm;
}

/* Port of DoBoulderDustAnimation in engine/overworld/push_boulder.asm. */
__attribute__((noinline, used)) void
port_do_boulder_dust_animation(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u8 sprite;
	port_u16 pointer;

	registers->a = memory[W_STATUS_FLAGS5];
	bit_zero(registers, registers->a);
	if ((registers->f & PORT_FLAG_Z) == 0)
		return;

	animate_farcall(registers, memory);
	discard_buttons(registers, memory);
	memory[W_JOY_IGNORE] = registers->a;
	reset_boulder_flags(registers, memory);
	memory[W_MISC_FLAGS] |= 0x80u;
	registers->a = memory[W_BOULDER_SPRITE_INDEX];
	sprite = registers->a;
	memory[H_SPRITE_INDEX] = registers->a;
	pointer = movement_byte2_pointer(registers, sprite);
	memory[pointer] = 0x10u;
	registers->a = SFX_CUT;
	play_cut_sound(registers, memory);
}
