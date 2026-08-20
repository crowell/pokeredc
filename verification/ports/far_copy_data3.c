#include "port_state.h"

struct far_copy_data3_state {
    struct cpu_register_state registers;
    port_u8 requested_bank;
    port_u8 loaded_bank;
    port_u8 rom_bank;
    port_u8 copy_b;
    port_u8 copy_c;
};

/* Port of FarCopyData3 in home/copy2.asm.
 *
 * Saves the bank and HL/DE pairs, invokes CopyData with the source/destination
 * pairs rearranged, then restores DE/HL and the saved AF. CopyData's B/C
 * result is explicit compositional state; no raw memory pointer is required. */

__attribute__((noinline, used)) void
port_far_copy_data3(struct far_copy_data3_state *state)
{
    port_u8 original_f = state->registers.f;
    port_u8 original_bank = state->loaded_bank;
    port_u8 original_d = state->registers.d;
    port_u8 original_e = state->registers.e;
    port_u8 original_h = state->registers.h;
    port_u8 original_l = state->registers.l;
    state->requested_bank = state->registers.a;
    state->rom_bank = state->requested_bank;
    state->loaded_bank = state->requested_bank;
    state->registers.b = state->copy_b;
    state->registers.c = state->copy_c;
    state->registers.d = original_d;
    state->registers.e = original_e;
    state->registers.h = original_h;
    state->registers.l = original_l;
    state->registers.a = original_bank;
    state->registers.f = original_f;
    state->loaded_bank = original_bank;
    state->rom_bank = original_bank;
}
