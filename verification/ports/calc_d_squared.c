#include "port_state.h"

/* Port of CalcDSquared in engine/pokemon/experience.asm.
 *
 * Initialises the 24-bit multiplicand to d (high bytes zero) and the
 * multiplier to d so that the trailing `jp Multiply` computes d*d. The
 * multiplication itself is Multiply's responsibility; this port covers the
 * setup that CalcDSquared performs before the tail call. */

#define CDS_H_MULTIPLICAND   0xff96u
#define CDS_H_MULTIPLICAND_1 0xff97u
#define CDS_H_MULTIPLICAND_2 0xff98u
#define CDS_H_MULTIPLIER     0xff99u

__attribute__((noinline, used)) void
port_calc_d_squared(struct cpu_register_state *state, port_u8 *memory)
{
    port_u8 d = state->d;
    memory[CDS_H_MULTIPLICAND] = 0;
    memory[CDS_H_MULTIPLICAND_1] = 0;
    memory[CDS_H_MULTIPLICAND_2] = d;
    memory[CDS_H_MULTIPLIER] = d;
    state->a = d;
    state->f = 0;
}
