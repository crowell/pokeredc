#include "port_state.h"

/* Port of Route5_Script in scripts/Route5.asm:
 *
 *   jp EnableAutoTextBoxDrawing
 */

void port_enable_auto_text_box_drawing(struct auto_text_box_state *);

__attribute__((noinline, used)) void
port_route5_script(struct cpu_register_state *state, port_u8 *memory)
{
	port_enable_auto_text_box_drawing(state, memory);
}
