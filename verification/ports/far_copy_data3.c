#include "port_state.h"

void port_copy_data(struct cpu_register_state *state, port_u8 *memory);

/* Port of FarCopyData3 in home/copy2.asm.
 *
 * Saves the bank and HL/DE pairs, invokes CopyData with the source/destination
 * pairs rearranged, executes the complete CopyData loop, then restores DE/HL
 * and the saved AF. */

__attribute__((noinline, used)) void
port_far_copy_data3(struct far_copy_data3_state *state, port_u8 *memory)
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
    state->registers.d = original_h;
    state->registers.e = original_l;
    state->registers.h = original_d;
    state->registers.l = original_e;
    port_copy_data(&state->registers, memory);
    state->registers.d = original_d;
    state->registers.e = original_e;
    state->registers.h = original_h;
    state->registers.l = original_l;
    state->registers.a = original_bank;
    state->registers.f = original_f;
    state->loaded_bank = original_bank;
    state->rom_bank = original_bank;
}
