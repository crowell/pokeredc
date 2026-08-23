#include "port_state.h"

/* Port of RedsHouse1F_Script in scripts/RedsHouse1F_Script.asm:
 *
 *   jp EnableAutoTextBoxDrawing
 */

void port_enable_auto_text_box_drawing(struct auto_text_box_state *);

#define W_AUTO_TEXT_BOX_DRAWING_CONTROL 0xcf0cu
#define W_DO_NOT_WAIT_FOR_BUTTON_PRESS  0xcc3cu

__attribute__((noinline, used)) void
port_reds_house1_f_script(struct cpu_register_state *state, port_u8 *memory)
{
	struct auto_text_box_state text_box;

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
