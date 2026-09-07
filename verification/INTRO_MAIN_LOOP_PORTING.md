# macOS C-port handoff — 2026-09-07

## Current acceptance result

This is **not yet a playable-through or proven 1:1 port**. The runtime uses
native C and original ROM assets; it does not execute the game's SM83 code.

Work is in the independent checkout `.worktrees/ds_port`, branch `dsp2`.
Upstream `ds4` commit `03b235366cf2cade298cde09a0a97b687148bc9b` is already
included. Preserve existing uncommitted work; no new commit/push was made.

Build/run from that checkout:

```sh
make -C verification mac
verification/build-mac/pokered-mac --rom pokered.gbc
make -C verification mac-test
```

The integration test now exercises:

- 353 original compressed pictures against their uncompressed bytes;
  both normal and mirrored alignment/interlace/VRAM transfers;
- synthetic mode-0 zero-run streams in both buffer orders;
- GetMonHeader's actual BaseStats bank and restored caller bank;
- every font-transfer chunk and all three window tilemap thirds;
- DMG sprite selection/overlap, raw-color priority, 8x16 flipping,
  ordinary window clipping and BG/window disable behavior;
- a complete 88-frame music fade followed by a queued bank change;
- interruption of the shooting star followed by the battle intro;
- Oak's original dialogue through 25 actual A/B acknowledgments,
  default player name and custom rival name, and arrival in the bedroom;
- the bedroom's initial-facing script and house map-script dispatch;
- Mom's pre-starter dialogue and TV text with manual acknowledgments,
  window configuration and map restoration; a branched fixture also walks
  to Mom with real D-pad input and dispatches her dialogue with A;
- walking from the bedroom through downstairs into Pallet Town.

These are regression tests, not an end-to-end SM83 equivalence proof.
AddressSanitizer/UndefinedBehaviorSanitizer runs cover this opening route.
Do not infer battle, saving, menus, other map scripts, or later-map correctness.
The native SDL application also completed a 330-frame macOS launch with no
window/audio initialization error. This required display access outside the
filesystem sandbox; the sandboxed launch correctly reported no available display.

## Implemented runtime work

- `platform/music.c` adapts the existing Audio1/2/3 handler snapshots to
  live WRAM, ROM command bytes and NRxx registers. It resumes all eight
  channels, calls FadeOutAudio and the battle engine's low-health alarm.
  `platform/apu.c` renders all four channels. Smoke tests no longer inject
  a test tone into game audio.
- `ports/uncompress_sprite_data.c` completes the two compressed bit planes
  through existing bit-reader/writer and unpacking ports.
  `ports/load_mon_front_sprite.c` and `platform/pictures.c` complete
  front-picture alignment and VRAM/tilemap placement.
- `platform/dialogue.c` retains text bank/command/character continuations.
  `port_place_string_resume` reuses the existing PlaceString handlers but
  returns at NextChar and waits for actual button edges at prompts.
  FAR commands no longer require overwriting bytes in a ROM window.
- `platform/oak.c` follows OakSpeech's ROM call/text order, including the
  original Nidorina cry with the displayed Nidorino, picture fades,
  default/custom names, case switching, name deletion and submission.
- The overworld composes real sprite updates, land/water collision,
  AdvancePlayerSprite, row/column redraw, map loading, stairs/door warps,
  and map music. Its tested route ends in Pallet Town.
- `platform/map_flow.c` dispatches the two house scripts by original
  bank/address. RedsHouse2FDefaultScript has a complete 14-byte leaf proof.
  Mom's pre-starter and TV text-ASM selectors resume original ROM text;
  DisplayTextIDInit and CloseTextDisplay now execute their tile/font
  transfers, bank changes and waits for actual input. Healing is missing.
- Title exit restores the window and BG1 auto-transfer destination. Leaving
  those in the title's old state caused later dialogue to overwrite the
  scrolling map. Visual captures now show dialogue and restored map views.

## Verification corrections and limits

Do not equate `status = "proven"` with a complete runtime function.

1. `UncompressSpriteFromDE` was proved only through its tail jump; runtime
   previously never decompressed anything. The newly composed decoder and
   LoadMonFrontSprite are explicitly `implemented_unproven` in ports.toml.
2. XorSpriteChunks and UnpackSpriteMode2, and their fixtures, read
   `d0a9` (unpack mode) instead of `d0a8` (load flags). Corrected from the
   actual ROM symbols. Their dependent ResetSpriteBufferPointers contract
   still must be independently audited, not merely assumed.
   The full corrected XOR matrix was interrupted after over an hour:
   UnpackSpriteMode2 and XOR 40-b1, 40-b2, 48-b1 had passed. XorSpriteChunks
   is downgraded pending completion of the larger cases; an interrupted
   test is not evidence of either a successful proof or a semantic mismatch.
   A focused 48-b2 retry was also interrupted; its stack trace remained in
   native angr/Z3 constraint solving. Keep its proof domain unchanged when
   improving harness performance; do not substitute a C-matching oracle.
3. OakSpeechSlidePicCommon's test hooks the **entire** assembly function
   with a handwritten model. Both it and C had wrong HRAM addresses and a
   left-copy no-op. Fixed behavior; renamed the check a symbolic model
   regression and downgraded its ledger status. An instruction-level proof
   is still required.
4. LoadMapData's old whole-copy-loop model repeated a C bug: it advanced
   the source by 32 instead of 20 and added another 12 to final DE.
   The test now executes the linked loop with individual SM83 instruction
   shims. Helper calls are still explicit boundaries.
5. TextCommandProcessor declared TextCommand_SOUND's 24-byte state as an
   8-byte register pointer. Added a typed adapter to prevent stack
   corruption. Audit other cross-file declarations for the same problem.
6. Runtime bank mapping is additional behavior not covered by legacy
   flat-memory proofs. In particular test nested farcalls and predefs with
   distinct bytes at the same address in different banks.
7. Shared Sm83LoadAFromImmediate/Sm83LoadAFromRegister adapters incorrectly
   cleared flags. They now preserve flags, as LD requires. Regression tests
   cover arbitrary source bytes and flags. The dependent rerun exposed
   CalcDSquared's incorrect F=0; it now preserves XOR A's Z flag. Its proof
   was strengthened with a linked-byte assertion and passes after the fix;
   the other 27 dependent cases passed. Never treat an older "proven" label
   as overriding a failure under corrected instruction semantics.
8. CopyVideoDataDouble and CopyScreenTileBufferToVRAM previously acknowledged
   fake waits without executing each scheduled chunk/third. Their runtime
   paths now call the VBlank transfer ports before proceeding. Host-frame
   timing is still synchronous and needs resumable integration.

## Next team: map scripts and first playable battle

The next mandatory gate is **PalletTown_Script** (`06:4e5b`).
The runtime now reaches RunMapScript dispatch but only the two house scripts
are connected. Unknown callbacks are logged once per bank/address; they do
not constitute executed game logic or validated progression.
Port and wire these in gameplay order:

1. `JoypadOverworld` / `RunMapScript` / `CallFunctionInTable`:
   extend the original banked map-script C dispatch in `map_flow.c`.
   Supply TryPushingBoulder, DoBoulderDustAnimation and RunNPCMovementScript
   preludes, plus original simulated-joypad indexing/override behavior.
   Do not interpret SM83 or treat an unimplemented callback as success.
2. Complete `RedsHouse1FMomHealScript`: text, fade, ReloadMapData, HealParty,
   healing music completion, map music restoration, fade-in and final text.
   Initial-facing/default/no-op and pre-starter Mom/TV paths are connected.
3. PalletTown's complete script table:
   `PalletTownDefaultScript`, `PalletTownOakHeyWaitScript`,
   `PalletTownOakWalksToPlayerScript`,
   `PalletTownOakNotSafeComeWithMeScript`,
   `PalletTownPlayerFollowsOakScript`, Daisy/no-op.
   Respect event flags, ShowObject/HideObject, joy-ignore masks and music.
4. Compose `MoveSprite`, `CalcPositionOfPlayerRelativeToNPC`,
   `FindPathToPlayer`, `ConvertNPCMovementDirectionsToJoypadMasks`,
   `StartSimulatingJoypadStates`, `PlayerStepOutFromDoor` and
   `PalletMovementScript_{OakMoveLeft,PlayerMoveLeft,WaitAndWalkToLab,
   WalkToLab,Done}`. Use the two original WalkToLab RLE lists through
   DecodeRLEList. Finish ShowObject/HideObject beyond callback snapshots.
   Implement PalletTownOakText's text-ASM tail: ten-frame delay,
   EmotionBubble, facing change and TextScriptEnd. An NPC walk and the
   60-frame emotion bubble must run for real frames while the player is locked.
5. OaksLab script table and text-ASM callbacks, choosing each starter,
   declining/confirming, party insertion, nickname flow, rival selection.
6. `NewBattle` / `InitBattle` through the actual turn/menu loop:
   send-out, move selection, damage, fainting, rewards, win/loss,
   cleanup and return to map scripts. Do not stop at dispatch flags.
7. Pallet/Route 1/Viridian progression, wild encounters and catching,
   healing, Oak's Parcel and Pokédex event chain.
8. Start-menu navigation, party/bag/player screens, options, PC storage,
   save/continue and persistent SRAM. No save path is currently validated.

Acceptance: scripted playthroughs for all three starters, first battle
win/loss, parcel delivery, catch/heal/save/quit/continue. Compare WRAM,
VRAM, OAM, bank state and game-visible transitions with the original ROM.

## Remaining opening/hardware fidelity work

- CopyVideoData and CopyVideoDataDouble still service their fake DelayFrame
  observations synchronously; expose these waits to the host frame pump.
- Text scrolling currently performs both row copies before its ten-frame
  wait; show the intermediate row at five frames. Substitutions print as
  a group. Support all text commands and resumable text-ASM C callbacks.
- Naming slides currently perform six passes synchronously and then wait.
  Preserve the three-frame display after each pass. Complete the Oak
  shrinking-to-overworld OAM timing against the ROM; sprite tiles and the
  50-frame PrepareOAMData continuation now execute.
- Title monster rotation/ball animation/cry and the scanline-specific
  version reveal are not complete. Intro interruption windows are closer,
  but no per-VBlank ROM trace has established exact timing.
- PPU is frame-based. The ten-sprites-per-line selection, DMG X/OAM ordering,
  raw-background-color priority and ordinary window clipping now have
  regression tests based on [Pan Docs OAM](https://github.com/gbdev/pandocs/blob/master/src/OAM.md)
  and [LCDC](https://github.com/gbdev/pandocs/blob/master/src/LCDC.md).
  Raster writes, pixel-fetch timing, window-row progression and WX=0/166
  hardware quirks still need independent reference traces.
- APU PCM is approximate mono: compare per-frame NR10–NR52/wave-RAM
  traces first, then envelope/sweep/length/DAC timing and stereo output.
  Finish home PlaySound SFX suppression during pending fades.
- DIV/TIMA/RNG, play time, frame pacing and SRAM banking need broader
  hardware equivalence checks.
- Test every warp/connection and battle-return path; the bedroom-to-town
  route does not establish correctness across all tilesets.

## Integration rules

- Keep original assets, tables and game behavior, including original bugs.
- A `*_called`/dispatch flag is a continuation request, not a completed call.
- Carry real bank state, predef registers, flags and WRAM effects across calls.
- Do not alter expected results merely to match C. Identify the linked
  instructions/symbols that justify a correction; remove self-confirming models.
- Maintain separate evidence for runtime regressions, memory safety,
  symbolic call-boundary contracts and full instruction equivalence.
- Record new functions without proofs as unproven; never upgrade the
  whole game based on passing leaf tests.
