#include "port_state.h"

/* Port of GetMonName in home/names.asm.
 *
 * Given a 1-based species id in [wNamedObjectIndex], copies that species' name
 * (NAME_LENGTH - 1 bytes) from the MonsterNames table into wNameBuffer and
 * terminates it with '@'. The ROM-bank switch around the table read is a no-op
 * for the observable (the name bytes come from the provided table image). */

#define GMN_W_NAMED_OBJECT_INDEX 0xd11eu
#define GMN_MONSTER_NAMES 0x421eu
#define GMN_NAME_LENGTH 11u
#define GMN_W_NAME_BUFFER 0xcd6du
#define GMN_TERMINATOR 0x50u /* pokered text terminator '$50' (rendered as '@') */

__attribute__((noinline, used)) void
port_get_mon_name(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	port_u8 raw = memory[GMN_W_NAMED_OBJECT_INDEX];
	port_u16 id = (port_u16)(raw - 1);
	port_u16 hl = (port_u16)(GMN_MONSTER_NAMES + (GMN_NAME_LENGTH - 1) * id);
	port_u16 de = GMN_W_NAME_BUFFER;
	for (port_u16 i = 0; i < GMN_NAME_LENGTH - 1; i++) {
		memory[de + i] = memory[hl + i];
	}
	memory[GMN_W_NAME_BUFFER + GMN_NAME_LENGTH - 1] = GMN_TERMINATOR;
}
