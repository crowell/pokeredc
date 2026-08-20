#include "port_state.h"

struct start_new_game_debug_state {
    struct cpu_register_state registers;
    port_u8 joy_pressed;
    port_u8 joy_held;
    port_u8 joy5;
    port_u8 cable_club_destination_map;
    port_u8 status_flags6;
    port_u8 entering_cable_club;
    port_u8 oak_speech_called;
    port_u8 delay_frames_called;
    port_u8 reset_sprite_called;
    port_u8 enter_map_called;
};

#define BIT_GAME_TIMER_COUNTING 1u

/* Port of StartNewGameDebug/SpecialEnterMap. OakSpeech, DelayFrames,
 * ResetPlayerSpriteData, and EnterMap are explicit call-boundary effects. */
__attribute__((noinline, used)) void
port_start_new_game_debug(struct start_new_game_debug_state *state)
{
    state->oak_speech_called = 1;
    state->delay_frames_called = 2;
    state->joy_pressed = 0;
    state->joy_held = 0;
    state->joy5 = 0;
    state->cable_club_destination_map = 0;
    state->status_flags6 |= (port_u8)(1u << BIT_GAME_TIMER_COUNTING);
    state->reset_sprite_called = 1;
    state->enter_map_called = 0;
    if (state->entering_cable_club == 0)
        state->enter_map_called = 1;
}
