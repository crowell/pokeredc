#include "port_state.h"

/* Port of SafariZoneEastRestHouse_Script in scripts/SafariZoneEastRestHouse.asm:
 *
 *   call EnableAutoTextBoxDrawing
 *   ret
 */

void port_enable_auto_text_box_drawing(struct auto_text_box_state *);

__attribute__((noinline, used)) void
port_safari_zone_east_rest_house_script(struct cpu_register_state *state, port_u8 *memory)
{
	struct auto_text_box_state text_box;

	text_box.registers = *state;
	text_box.auto_text_box_drawing_control =
	    memory[0xcf0cu];
	text_box.do_not_wait_for_button_press =
	    memory[0xcc3cu];

	port_enable_auto_text_box_drawing(&text_box);

	*state = text_box.registers;
	memory[0xcf0cu] = text_box.auto_text_box_drawing_control;
	memory[0xcc3cu] = text_box.do_not_wait_for_button_press;
}
