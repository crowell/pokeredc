#include "port_state.h"

/* Port of GetMachineName in home/names.asm.
 *
 * Copies the two-character "TM"/"HM" prefix for the machine whose id is held
 * in [wNamedObjectIndex] into wNameBuffer, then appends the zero-padded
 * two-digit machine number and the '@' text terminator. HMs (id < TM01) have
 * NUM_HMS added so the shared TM digit-printing code works. The prefix strings
 * live in ROM and the two-byte copy is inlined (mirroring the `call CopyData`). */

#define W_NAMED_OBJECT_INDEX 0xd11eu
#define W_NAME_BUFFER 0xcd6du
#define HIDDEN_PREFIX 0x303eu
#define TECHNICAL_PREFIX 0x303cu
#define TM01 0xc9u
#define NUM_HMS 5u
#define TEXT_TERMINATOR 0x50u /* '@' in the pokered text charset */
#define TEXT_DIGIT_ZERO 0xf6u /* '0' in the pokered text charset */

__attribute__((noinline, used)) void
port_get_machine_name(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	port_u8 id = memory[W_NAMED_OBJECT_INDEX];
	port_u8 digit_id;
	port_u16 prefix_src;
	if (id < TM01) {
		/* HM: bump the id so the shared TM printing code works. */
		digit_id = (port_u8)(id + NUM_HMS);
		prefix_src = HIDDEN_PREFIX;
	} else {
		digit_id = id;
		prefix_src = TECHNICAL_PREFIX;
	}
	memory[W_NAME_BUFFER + 0] = memory[prefix_src + 0];
	memory[W_NAME_BUFFER + 1] = memory[prefix_src + 1];

	/* Two-digit, zero-padded machine number after the prefix. */
	port_u8 v = (port_u8)(digit_id - (TM01 - 1));
	port_u8 b = TEXT_DIGIT_ZERO;
	while (v >= 10) {
		v = (port_u8)(v - 10);
		b = (port_u8)(b + 1);
	}
	memory[W_NAME_BUFFER + 2] = b;
	memory[W_NAME_BUFFER + 3] = (port_u8)(v + TEXT_DIGIT_ZERO);
	memory[W_NAME_BUFFER + 4] = TEXT_TERMINATOR;
	/* Restore the original object index (asm pops the saved value). */
	memory[W_NAMED_OBJECT_INDEX] = id;
}
