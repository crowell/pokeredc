#include "port_state.h"

/* Port of StartNewGameDebug in engine/menus/main_menu.asm.
 *
 * This is the debug-mode new-game entry point. After the (unported) OakSpeech,
 * it falls through into SpecialEnterMap which zeroes the joypad buffers and the
 * cable-club destination, starts the game timer, resets player sprite data and
 * (unless entering a cable club) enters the map. The deterministic observable
 * memory writes modeled here are the joypad/flag/status bytes; OakSpeech,
 * ResetPlayerSpriteData, DelayFrames and EnterMap are unported callees whose
 * internal effects are deferred. The equivalence proof for StartNewGameDebug
 * is pending. */

#define H_JOY_PRESSED          0xffb3u
#define H_JOY_HELD             0xffb4u
#define H_JOY5                 0xffb5u
#define W_CABLE_CLUB_DEST_MAP  0xd72du
#define W_STATUS_FLAGS6        0xd732u
#define W_ENTERING_CABLE_CLUB  0xcc47u
#define BIT_GAME_TIMER_COUNTING 0x01u  /* bit 0 */

__attribute__((noinline, used)) void
port_start_new_game_debug(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;

	/* call OakSpeech -- deferred. */
	/* ld c, 20; call DelayFrames -- timing, deferred. */

	/* SpecialEnterMap (fallthrough) deterministic writes: */
	/* xor a; ldh [hJoyPressed/hJoyHeld/hJoy5], a; ld [wCableClubDestinationMap], a */
	memory[H_JOY_PRESSED] = 0;
	memory[H_JOY_HELD] = 0;
	memory[H_JOY5] = 0;
	memory[W_CABLE_CLUB_DEST_MAP] = 0;

	/* ld hl, wStatusFlags6; set BIT_GAME_TIMER_COUNTING, [hl] */
	memory[W_STATUS_FLAGS6] =
		(port_u8)(memory[W_STATUS_FLAGS6] | BIT_GAME_TIMER_COUNTING);

	/* call ResetPlayerSpriteData -- deferred. */
	/* ld c, 20; call DelayFrames -- timing, deferred. */

	/* ld a, [wEnteringCableClub]; and a; ret nz */
	if (memory[W_ENTERING_CABLE_CLUB] != 0)
		return;

	/* jp EnterMap -- deferred. */
}
