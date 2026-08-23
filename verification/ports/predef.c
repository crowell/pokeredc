#include "port_state.h"

/*
 * Port of Predef in home/predef.asm:
 *
 *   ld [wPredefID], a
 *   ldh a, [hLoadedROMBank]
 *   ld [wPredefParentBank], a
 *   push af
 *   ld a, BANK(GetPredefPointer)      ; $13
 *   ldh [hLoadedROMBank], a
 *   ld [rROMB], a
 *   call GetPredefPointer             ; proven composition
 *   ld a, [wPredefBank]
 *   ldh [hLoadedROMBank], a
 *   ld [rROMB], a
 *   ld de, .done
 *   push de
 *   jp hl                             ; predef body: continuation boundary
 * .done:
 *   pop af                            ; A = parent bank; F = entry flags
 *   ldh [hLoadedROMBank], a
 *   ld [rROMB], a
 *   ret
 *
 * The dispatch target is banked-out code, so port_predef_target_boundary
 * marks the compositional cut where the proven predef body takes over.
 */

void port_get_predef_pointer(struct predef_pointer_state *);

#define W_PREDEF_ID        0xcc4eu
#define W_PREDEF_HL        0xcc4fu
#define W_PREDEF_DE        0xcc51u
#define W_PREDEF_BC        0xcc53u
#define W_PREDEF_PARENT_BANK 0xcf12u
#define W_PREDEF_BANK      0xd0b7u
#define H_LOADED_ROM_BANK  0xffb8u
#define R_ROMB             0x2000u

static volatile port_u8 predef_boundary_sink;

__attribute__((noinline, used)) void
port_predef_target_boundary(struct cpu_register_state *state)
{
	/* Compositional seam for the banked `jp hl` dispatch. The proof hooks
	 * this seam to apply the predef body's proven transition; the shipped
	 * game build replaces it with the real per-predef implementation. The
	 * volatile store keeps the call site intact for the hook. */
	predef_boundary_sink = state->a;
}

__attribute__((noinline, used)) void
port_predef(struct predef_state *state, port_u8 *memory)
{
	struct predef_pointer_state pointer;
	port_u8 parent_bank;
	port_u8 pushed_a;
	port_u8 pushed_f;

	/* ld [wPredefID], a */
	memory[W_PREDEF_ID] = state->registers.a;

	/* ldh a, [hLoadedROMBank]; ld [wPredefParentBank], a */
	parent_bank = memory[H_LOADED_ROM_BANK];
	memory[W_PREDEF_PARENT_BANK] = parent_bank;

	/* push af */
	pushed_a = parent_bank;
	pushed_f = state->registers.f;

	/* ld a, BANK(GetPredefPointer); ldh [hLoadedROMBank], a; ld [rROMB], a */
	state->registers.a = 0x13u;
	memory[H_LOADED_ROM_BANK] = 0x13u;
	memory[R_ROMB] = 0x13u;

	pointer.registers = state->registers;
	pointer.predef_id = memory[W_PREDEF_ID];
	pointer.fetched_bank = state->fetched_bank;
	pointer.fetched_pointer_low = state->fetched_pointer_low;
	pointer.fetched_pointer_high = state->fetched_pointer_high;
	port_get_predef_pointer(&pointer);
	state->registers = pointer.registers;
	memory[W_PREDEF_HL] = pointer.saved_h;
	memory[(W_PREDEF_HL) + 1] = pointer.saved_l;
	memory[W_PREDEF_DE] = pointer.saved_d;
	memory[(W_PREDEF_DE) + 1] = pointer.saved_e;
	memory[W_PREDEF_BC] = pointer.saved_b;
	memory[(W_PREDEF_BC) + 1] = pointer.saved_c;
	memory[W_PREDEF_BANK] = pointer.predef_bank;

	/* ld a, [wPredefBank]; ldh [hLoadedROMBank], a; ld [rROMB], a */
	parent_bank = memory[W_PREDEF_BANK];
	state->registers.a = parent_bank;
	memory[H_LOADED_ROM_BANK] = parent_bank;
	memory[R_ROMB] = parent_bank;

	/* push de (.done address) */
	state->registers.d = 0x3eu;
	state->registers.e = 0x8du;

	/* jp hl — dispatch into the predef body. */
	port_predef_target_boundary(&state->registers);

	/* .done: pop af restores A = parent bank and entry flags. */
	state->registers.a = pushed_a;
	state->registers.f = pushed_f;

	/* ldh [hLoadedROMBank], a; ld [rROMB], a; ret */
	memory[H_LOADED_ROM_BANK] = state->registers.a;
	memory[R_ROMB] = state->registers.a;
}
