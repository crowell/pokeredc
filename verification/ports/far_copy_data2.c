#include "port_state.h"

struct far_copy_data2_state {
    struct cpu_register_state registers;
    port_u8 requested_bank;
    port_u8 loaded_bank;
    port_u8 rom_bank;
    port_u8 copy_a;
    port_u8 copy_f;
    port_u8 copy_b;
    port_u8 copy_c;
    port_u8 copy_d;
    port_u8 copy_e;
    port_u8 copy_h;
    port_u8 copy_l;
};

/* Port of FarCopyData2 in home/copy2.asm.
 *
 * Saves the currently loaded bank, switches to A, invokes CopyData, then
 * restores the saved bank. CopyData's returned registers are explicit
 * compositional state; the contract contains no raw Game Boy memory pointer. */

__attribute__((noinline, used)) void
port_far_copy_data2(struct far_copy_data2_state *state)
{
    port_u8 original_f = state->registers.f;
    port_u8 original_bank = state->loaded_bank;
    state->requested_bank = state->registers.a;
    state->rom_bank = state->requested_bank;
    state->loaded_bank = state->requested_bank;
    state->registers.a = state->copy_a;
    state->registers.f = state->copy_f;
    state->registers.b = state->copy_b;
    state->registers.c = state->copy_c;
    state->registers.d = state->copy_d;
    state->registers.e = state->copy_e;
    state->registers.h = state->copy_h;
    state->registers.l = state->copy_l;
    state->registers.a = original_bank;
    state->registers.f = original_f;
    state->loaded_bank = original_bank;
    state->rom_bank = original_bank;
}
