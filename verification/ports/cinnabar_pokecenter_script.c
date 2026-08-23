#include "port_state.h"

/* Port of CinnabarPokecenter_Script in scripts/CinnabarPokecenter.asm:
 *
 *   call Serial_TryEstablishingExternallyClockedConnection
 *   jp EnableAutoTextBoxDrawing
 *
 * Composition of two proven ports. Serial's contract models its hardware
 * writes (rSB=$ff01 via background_palette, hSerialReceiveData=$ffad via
 * object_palette0, rSC=$ff02 via object_palette1) and leaves A=0 with Z set;
 * EnableAutoTextBoxDrawing clears wAutoTextBoxDrawingControl and
 * wDoNotWaitForButtonPressAfterDisplayingText.
 */

void port_serial_try_establishing_externally_clocked_connection(
	struct black_screen_state *);
void port_enable_auto_text_box_drawing(struct auto_text_box_state *);

#define W_AUTO_TEXT_BOX_DRAWING_CONTROL 0xcf0cu
#define W_DO_NOT_WAIT_FOR_BUTTON_PRESS  0xcc3cu
#define R_SB                    0xff01u
#define H_SERIAL_RECEIVE_DATA   0xffadu
#define R_SC                    0xff02u

__attribute__((noinline, used)) void
port_cinnabar_pokecenter_script(struct cpu_register_state *state,
			       port_u8 *memory)
{
	struct black_screen_state serial;
	struct auto_text_box_state text_box;

	serial.registers = *state;
	serial.background_palette = memory[R_SB];
	serial.object_palette0 = memory[H_SERIAL_RECEIVE_DATA];
	serial.object_palette1 = memory[R_SC];
	port_serial_try_establishing_externally_clocked_connection(&serial);
	memory[R_SB] = serial.background_palette;
	memory[H_SERIAL_RECEIVE_DATA] = serial.object_palette0;
	memory[R_SC] = serial.object_palette1;
	*state = serial.registers;

	text_box.registers = *state;
	text_box.auto_text_box_drawing_control =
	    memory[W_AUTO_TEXT_BOX_DRAWING_CONTROL];
	text_box.do_not_wait_for_button_press =
	    memory[W_DO_NOT_WAIT_FOR_BUTTON_PRESS];
	port_enable_auto_text_box_drawing(&text_box);
	*state = text_box.registers;
	memory[W_AUTO_TEXT_BOX_DRAWING_CONTROL] =
	    text_box.auto_text_box_drawing_control;
	memory[W_DO_NOT_WAIT_FOR_BUTTON_PRESS] =
	    text_box.do_not_wait_for_button_press;
}
