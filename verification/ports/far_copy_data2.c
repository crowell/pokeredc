#include "port_state.h"

void port_copy_data(struct cpu_register_state *state, port_u8 *memory);

/* Port of FarCopyData2 in home/copy2.asm.
 *
 * Saves the currently loaded bank, switches to A, executes CopyData's full
 * transfer loop, then restores the saved bank and AF. */

__attribute__((noinline, used)) void
port_far_copy_data2(struct far_copy_data2_state *state, port_u8 *memory)
{
    port_u8 original_f = state->registers.f;
    port_u8 original_bank = state->loaded_bank;
    state->requested_bank = state->registers.a;
    state->rom_bank = state->requested_bank;
    state->loaded_bank = state->requested_bank;
    port_copy_data(&state->registers, memory);
    state->registers.a = original_bank;
    state->registers.f = original_f;
    state->loaded_bank = original_bank;
    state->rom_bank = original_bank;
}
