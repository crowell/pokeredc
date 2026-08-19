#include "port_state.h"

/* Port of AISwitchIfEnoughMons in engine/battle/trainer_ai.asm.
 *
 * Iterates c enemy party slots, each a 0x2c-byte struct beginning at
 * wEnemyMonOT (0xd8a5), and counts how many have a non-zero leading 16-bit
 * field into d. If that count reaches 2 the original tails into the switch
 * routine via `jp nc` (modelled here as the path boundary). On the
 * fall-through path `cp 2 ; and a` is flag-only bookkeeping: `and a` is
 * A = A AND A, so A is left equal to d. A therefore equals d on every exit.
 * The loop only reads memory; nothing is written. */

#define AISEM_PARTY_COUNT 0xd89cu
#define AISEM_MON_OT      0xd8a5u
#define AISEM_STRIDE      0x2cu

__attribute__((noinline, used)) void
port_ai_switch_if_enough_mons(struct cpu_register_state *state, port_u8 *memory)
{
    port_u8 c = memory[AISEM_PARTY_COUNT];
    port_u16 hl = AISEM_MON_OT;
    port_u8 d = 0;
    while (c != 0) {
        port_u8 lo = memory[hl];
        port_u8 hi = memory[hl + 1];
        if ((port_u8)(lo | hi) != 0) {
            d++;
        }
        hl += AISEM_STRIDE;
        c--;
    }
    /* ld a, d ; cp 2 ; jp nc, switch (boundary) ; and a ; ret */
    state->a = d;
    state->d = d;
    state->c = 0;
    state->h = (port_u8)(hl >> 8);
    state->l = (port_u8)(hl & 0xff);
}
