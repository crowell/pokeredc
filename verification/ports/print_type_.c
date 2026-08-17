#include "port_state.h"

/*
 * Port of PrintType_ in engine/battle/print_type.asm:
 *
 *   add a                       ; type index * 2
 *   ld hl, TypeNames
 *   ld e, a
 *   ld d, 0
 *   add hl, de                  ; hl = TypeNames + type*2
 *   ld a, [hli]                 ; de = [hl] (pointer to the type-name string)
 *   ld e, a
 *   ld d, [hl]
 *   pop hl                      ; restore the destination pushed by the caller
 *   jp PlaceString
 *
 * The destination address is provided here in saved_h:saved_l (the value the
 * calling PrintType pushed). The type-name pointer is read from the TypeNames
 * table (2-byte little-endian entries) and the name is then placed into the
 * destination via port_place_string, which is the tail continuation.
 */

#define TYPE_NAMES 0x7dae

extern void port_place_string(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_print_type_(struct print_type_state *state, port_u8 *memory)
{
	port_u16 entry = (port_u16)(TYPE_NAMES +
		(port_u16)((port_u16)state->registers.a * 2));
	port_u16 name_ptr = (port_u16)(memory[entry] |
		((port_u16)memory[entry + 1] << 8));

	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
	state->registers.d = (port_u8)(name_ptr >> 8);
	state->registers.e = (port_u8)name_ptr;

	port_place_string(&state->registers, memory);
}
