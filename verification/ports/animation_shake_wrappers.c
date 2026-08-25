#include "port_state.h"

void port_get_predef_pointer(struct predef_pointer_state *);
void port_predef_shake_screen_vertically_private(
	struct predef_shake_vertical_state *);

/* Port of AnimationShakeScreenVertically and its predef_jump dispatch. */
__attribute__((noinline, used)) void
port_animation_shake_screen_vertically(
	struct animation_shake_vertical_state *state)
{
	struct predef_pointer_state pointer;
	port_u8 parent_bank = state->loaded_rom_bank;
	port_u8 entry_flags = state->shake.registers.f;

	/* ld a, $21; jp Predef: latch the ID and enter the pointer-table bank. */
	state->predef_id = 0x21u;
	state->predef_parent_bank = parent_bank;
	state->shake.registers.a = 0x13u;
	state->loaded_rom_bank = 0x13u;
	state->rom_bank = 0x13u;

	/* GetPredefPointer with the fixed table entry: dbw $12, $40ff. */
	pointer.registers = state->shake.registers;
	pointer.predef_id = state->predef_id;
	pointer.fetched_bank = 0x12u;
	pointer.fetched_pointer_low = 0xffu;
	pointer.fetched_pointer_high = 0x40u;
	port_get_predef_pointer(&pointer);
	state->shake.registers = pointer.registers;
	state->shake.predef[0] = pointer.saved_h;
	state->shake.predef[1] = pointer.saved_l;
	state->shake.predef[2] = pointer.saved_d;
	state->shake.predef[3] = pointer.saved_e;
	state->shake.predef[4] = pointer.saved_b;
	state->shake.predef[5] = pointer.saved_c;
	state->predef_bank = pointer.predef_bank;

	/* Switch to the target bank and model the pushed .done continuation. */
	state->loaded_rom_bank = state->predef_bank;
	state->rom_bank = state->predef_bank;
	state->shake.registers.a = state->predef_bank;
	state->shake.registers.d = 0x3eu;
	state->shake.registers.e = 0x8du;
	port_predef_shake_screen_vertically_private(&state->shake);

	/* Predef.done restores the pushed parent-bank A/F pair and ROM bank. */
	state->shake.registers.a = parent_bank;
	state->shake.registers.f = entry_flags;
	state->loaded_rom_bank = parent_bank;
	state->rom_bank = parent_bank;
}
