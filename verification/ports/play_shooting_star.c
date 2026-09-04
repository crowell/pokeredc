#include "port_state.h"

void port_run_palette_command(struct cpu_register_state *, port_u8 *);
void port_load_copyright_and_text_box_tiles(struct cpu_register_state *, port_u8 *);
void port_delay_frames(struct delay_frame_state *, const port_u8 *);
void port_clear_screen(struct cpu_register_state *, port_u8 *);
void port_disable_lcd(struct disable_lcd_state *);
void port_intro_draw_black_bars(struct cpu_register_state *, port_u8 *);
void port_load_intro_graphics(struct cpu_register_state *, port_u8 *);
void port_enable_lcd(struct black_screen_state *);
void port_animate_shooting_star(struct cpu_register_state *, port_u8 *);
void port_play_sound(struct play_sound_state *);
void port_intro_clear_middle_of_screen(struct cpu_register_state *, port_u8 *);
void port_clear_sprites(struct clear_sprites_state *);
void port_delay3(struct cpu_register_state *, port_u8 *);

#define R_BGP 0xff47u
#define R_LCDC 0xff40u
#define W_CUR_OPPONENT 0xd059u
#define W_AUDIO_ROM_BANK 0xc0efu
#define W_AUDIO_SAVED_ROM_BANK 0xc0f0u
#define W_NEW_SOUND_ID 0xc0eeu
#define MUSIC_INTRO_BATTLE_BANK 0x1fu
#define MUSIC_INTRO_BATTLE 0xdcu
#define W_SHADOW_OAM 0xc300u
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u

static void
delay_frames(struct cpu_register_state *registers, port_u8 *memory,
	port_u8 count)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	delay.registers = *registers;
	delay.registers.c = count;
	delay.vblank_occurred = memory[0xffd6u];
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	*registers = delay.registers;
	memory[0xffd6u] = delay.vblank_occurred;
}

__attribute__((noinline, used)) void
port_play_shooting_star(struct cpu_register_state *registers, port_u8 *memory)
{
	struct disable_lcd_state disable;
	struct black_screen_state enable;
	struct clear_sprites_state sprites;
	struct play_sound_state sound;
	port_u8 carry;

	registers->b = 0x0c;
	port_run_palette_command(registers, memory);
	port_load_copyright_and_text_box_tiles(registers, memory);
	registers->a = 0xe4;
	memory[R_BGP] = registers->a;
	delay_frames(registers, memory, 180);
	port_clear_screen(registers, memory);

	disable.registers = *registers;
	disable.interrupt_flags = memory[0xff0fu];
	disable.interrupt_enable = memory[0xffffu];
	disable.lcd_control = memory[R_LCDC];
	port_disable_lcd(&disable);
	*registers = disable.registers;
	memory[0xff0fu] = disable.interrupt_flags;
	memory[0xffffu] = disable.interrupt_enable;
	memory[R_LCDC] = disable.lcd_control;

	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	memory[W_CUR_OPPONENT] = 0;
	port_intro_draw_black_bars(registers, memory);
	port_load_intro_graphics(registers, memory);

	enable.registers = *registers;
	enable.background_palette = memory[R_LCDC];
	enable.object_palette0 = memory[0xff48u];
	enable.object_palette1 = memory[0xff49u];
	port_enable_lcd(&enable);
	*registers = enable.registers;
	memory[R_LCDC] = enable.background_palette;

	memory[R_LCDC] &= (port_u8)~(1u << 5);
	memory[R_LCDC] |= (port_u8)(1u << 3);
	delay_frames(registers, memory, 64);
	port_animate_shooting_star(registers, memory);
	carry = registers->f & PORT_FLAG_C;
	if (carry == 0)
		delay_frames(registers, memory, 40);

	memory[W_AUDIO_ROM_BANK] = MUSIC_INTRO_BATTLE_BANK;
	memory[W_AUDIO_SAVED_ROM_BANK] = MUSIC_INTRO_BATTLE_BANK;
	memory[W_NEW_SOUND_ID] = MUSIC_INTRO_BATTLE;
	sound.registers = *registers;
	sound.registers.a = MUSIC_INTRO_BATTLE;
	sound.new_sound_id = memory[W_NEW_SOUND_ID];
	sound.audio_rom_bank = memory[W_AUDIO_ROM_BANK];
	sound.fade_control = memory[0xcfc7u];
	sound.fade_reload = memory[0xcfc8u];
	sound.fade_counter = memory[0xcfc9u];
	sound.last_music_sound_id = memory[0xcfcau];
	for (port_u8 i = 0; i < 4; ++i)
		sound.channel_sound_ids[i] = memory[0xc026u + i];
	sound.saved_rom_bank = memory[0xffb9u];
	sound.loaded_rom_bank = memory[H_LOADED_ROM_BANK];
	sound.rom_bank = memory[R_ROMB];
	sound.audio_saved_rom_bank = memory[W_AUDIO_SAVED_ROM_BANK];
	port_play_sound(&sound);
	*registers = sound.registers;
	memory[W_NEW_SOUND_ID] = sound.new_sound_id;
	memory[W_AUDIO_ROM_BANK] = sound.audio_rom_bank;
	memory[W_AUDIO_SAVED_ROM_BANK] = sound.audio_saved_rom_bank;
	memory[0xcfc7u] = sound.fade_control;
	memory[0xcfc8u] = sound.fade_reload;
	memory[0xcfc9u] = sound.fade_counter;
	memory[0xcfcau] = sound.last_music_sound_id;
	for (port_u8 i = 0; i < 4; ++i)
		memory[0xc026u + i] = sound.channel_sound_ids[i];
	memory[0xffb9u] = sound.saved_rom_bank;
	memory[H_LOADED_ROM_BANK] = sound.loaded_rom_bank;
	memory[R_ROMB] = sound.rom_bank;

	port_intro_clear_middle_of_screen(registers, memory);
	sprites.registers = *registers;
	port_clear_sprites(&sprites);
	*registers = sprites.registers;
	for (unsigned i = 0; i < sizeof sprites.oam; ++i)
		memory[W_SHADOW_OAM + i] = sprites.oam[i];
	port_delay3(registers, memory);
}
