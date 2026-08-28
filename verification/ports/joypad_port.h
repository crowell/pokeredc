#ifndef POKERED_VERIFICATION_PORTS_JOYPAD_PORTS_H
#define POKERED_VERIFICATION_PORTS_JOYPAD_PORTS_H

#include "port_state.h"

/* Absolute Game Boy addresses of the joypad-related HRAM/WRAM variables.
 * The native harness exposes a flat buffer indexed by absolute address, so a
 * read of `ldh [hJoyInput]` is `memory[0xfff8]`. */
#define H_JOYINPUT           0xfff8
#define H_JOYLAST            0xffb1
#define H_JOYRELEASED        0xffb2
#define H_JOYPRESSED         0xffb3
#define H_JOYHELD            0xffb4
#define H_JOY5               0xffb5
#define H_JOY6               0xffb6
#define H_JOY7               0xffb7
#define H_DOWNARROWBLINK1    0xff8b
#define H_DOWNARROWBLINK2    0xff8c
#define H_FRAMEOUNTER        0xffd5
#define H_SOFTRESET          0xff8a
#define W_STATUSFLAGS5       0xd730
#define W_JOYIGNORE          0xcd6b
#define W_TOWNMAPBLINK       0xd09b
#define W_LINKSTATE          0xd12b

/* Joypad button-bit constants (combined input byte: directions in the high
 * nibble, buttons in the low nibble). */
#define PAD_A                0x01
#define PAD_B                0x02
#define PAD_AB               0x03 /* PAD_A | PAD_B */
#define PAD_BUTTONS          0x0f /* all four buttons held -> soft reset */
#define BIT_DISABLE_JOYPAD   5

/* Output observable of _Joypad (modeled by port_joypad). The joypad state is
 * also mirrored into HRAM at the addresses above. */
struct joypad_update_state {
	port_u8 joy_input;
	port_u8 joy_last;
	port_u8 joy_released;
	port_u8 joy_pressed;
	port_u8 joy_held;
};

/* PC-portable state for JoypadLowSensitivity; Joypad itself is an entry boundary. */
struct joypad_low_sensitivity_state {
	port_u8 joy7;
	port_u8 joy6;
	port_u8 pressed;
	port_u8 held;
	port_u8 joy5;
	port_u8 frame_counter;
};

/* Output observable of WaitForTextScrollButtonPress; polling is compositional. */
struct wait_for_text_scroll_state {
	struct cpu_register_state registers;
	port_u8 down_arrow_blink1;
	port_u8 down_arrow_blink2;
	port_u8 joy5;
	port_u8 wait_b;
	port_u8 wait_c;
	port_u8 wait_d;
	port_u8 wait_e;
	port_u8 wait_h;
	port_u8 wait_l;
};

/* Host-polled input sequence for HoldTextDisplayOpen. */
struct hold_text_display_open_state {
	struct cpu_register_state registers;
	port_u8 joy_inputs[8];
	port_u8 joy_input_count;
};

/* State for the AfterDisplayingTextID continuation into HoldTextDisplayOpen. */
struct after_displaying_text_id_state {
	struct cpu_register_state registers;
	port_u8 joy_inputs[8];
	port_u8 joy_input_count;
};

/* Output observable of ManualTextScroll; wait/play/delay callees are explicit. */
struct manual_text_scroll_state {
	struct cpu_register_state registers;
	port_u8 link_state;
	port_u8 wait_a;
	port_u8 wait_f;
	port_u8 wait_b;
	port_u8 wait_c;
	port_u8 wait_d;
	port_u8 wait_e;
	port_u8 wait_h;
	port_u8 wait_l;
	port_u8 wait_called;
	port_u8 sound_called;
	port_u8 delay_frames;
};

void port_joypad(struct joypad_update_state *state, port_u8 *memory);
void port_joypad_low_sensitivity(struct joypad_low_sensitivity_state *state);
void port_wait_for_text_scroll_button_press(struct wait_for_text_scroll_state *state);
void port_manual_text_scroll(struct manual_text_scroll_state *state);

#endif
