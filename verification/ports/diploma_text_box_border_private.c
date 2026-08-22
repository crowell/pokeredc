#include "port_state.h"

struct diploma_text_box_border_private_state {
	struct cpu_register_state registers;
};

/* Port of Diploma_TextBoxBorder through GetPredefRegisters entry. */
__attribute__((noinline, used)) void
port_diploma_text_box_border_private(
	struct diploma_text_box_border_private_state *state)
{
	(void)state;
}
