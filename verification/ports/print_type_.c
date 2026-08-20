#include "port_state.h"

#define TYPE_NAMES 0x7daeu

/* Port of PrintType_ in engine/battle/print_type.asm.
 *
 * The caller supplies the TypeNames table bytes fetched by the assembly path
 * and the saved destination HL in print_type_state. This removes the old raw
 * Game Boy memory-pointer dependency and makes the contract PC-portable. */

__attribute__((noinline, used)) void
port_print_type_(struct print_type_state *state)
{
    port_u8 original_a = state->registers.a;
    port_u16 doubled = (port_u16)original_a + original_a;
    port_u8 flags = 0;
    if ((port_u8)doubled == 0)
        flags |= PORT_FLAG_Z;
    if ((original_a & 0x0f) + (original_a & 0x0f) > 0x0f)
        flags |= PORT_FLAG_H;
    if (doubled > 0xff)
        flags |= PORT_FLAG_C;
    state->registers.a = (port_u8)doubled;

    port_u16 hl = (port_u16)(TYPE_NAMES + state->registers.a);
    port_u16 de = state->registers.a;
    port_u32 sum = (port_u32)hl + de;
    flags = (flags & PORT_FLAG_Z);
    if ((hl & 0x0fffu) + (de & 0x0fffu) > 0x0fffu)
        flags |= PORT_FLAG_H;
    if (sum > 0xffffu)
        flags |= PORT_FLAG_C;
    state->registers.f = flags;
    state->registers.h = (port_u8)(sum >> 8);
    state->registers.l = (port_u8)sum;
    state->registers.a = state->fetched_low;
    state->registers.e = state->fetched_low;
    state->registers.d = state->fetched_high;
    state->registers.h = state->saved_h;
    state->registers.l = state->saved_l;
    state->dispatched = 1;
}
