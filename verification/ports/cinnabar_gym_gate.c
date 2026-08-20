#include "port_state.h"

struct cinnabar_gym_gate_state {
    struct cpu_register_state registers;
    port_u8 map_width;
    port_u8 gate_unlocked[6];
    port_u8 new_tile_block[6];
    port_u8 overworld_block[6];
    port_u8 map_offset_lo[6];
    port_u8 map_offset_hi[6];
    port_u8 gate_index;
    port_u8 backup_gate_index;
};

static const port_u8 gym_gate_x[6] = {9, 6, 6, 3, 2, 2};
static const port_u8 gym_gate_y[6] = {3, 3, 6, 8, 6, 3};
static const port_u8 gym_gate_block[6] = {0x54, 0x54, 0x54, 0x5f, 0x54, 0x54};

#define OPEN_GATE_BLOCK 0x0eu

/* Port of UpdateCinnabarGymGateTileBlocks_ in
 * engine/events/hidden_events/cinnabar_gym_quiz.asm. The event-flag and
 * ReplaceTileBlock boundaries are represented by explicit per-gate state. */
__attribute__((noinline, used)) void
port_update_cinnabar_gym_gate_tile_blocks(struct cinnabar_gym_gate_state *state)
{
    port_u16 stride = (port_u16)state->map_width + 6u;
    state->gate_index = 6;
    for (int idx = 6; idx >= 1; idx--) {
        int slot = idx - 1;
        port_u16 offset = (port_u16)(3u * stride + 3u +
            (port_u16)gym_gate_y[slot] * stride + gym_gate_x[slot]);
        port_u8 block = state->gate_unlocked[slot]
            ? OPEN_GATE_BLOCK : gym_gate_block[slot];
        state->new_tile_block[slot] = block;
        state->overworld_block[slot] = block;
        state->map_offset_lo[slot] = (port_u8)offset;
        state->map_offset_hi[slot] = (port_u8)(offset >> 8);
        state->backup_gate_index = (port_u8)idx;
        state->gate_index = (port_u8)(idx - 1);
    }
}
