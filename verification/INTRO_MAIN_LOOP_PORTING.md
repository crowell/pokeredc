# Intro and Main-Loop C Port Handoff

This document is the integration contract for reaching a byte-for-byte-faithful opening and the first controllable frame in Red's House 2F. It supplements the generated, repository-wide [PORTING_BACKLOG.md](PORTING_BACKLOG.md); regenerate that file with `make -C verification backlog` after changing `verification/ports.toml`.

## What the macOS runtime now does

`verification/platform/game.c` starts from `Init`, enters a frame-resumable C implementation of the real `PlayIntro` order, and then enters the title screen. The runtime uses ROM data rather than replacement art for:

- all three copyright lines;
- Game Freak logo and shooting-star graphics/OAM;
- Gengar, Nidorino, and all seven Nidorino movement arrays;
- the three Gengar tilemaps;
- the title logos, player OAM, copyright row, version graphics, and title bounce table.

`verification/platform/apu.c` synthesizes all four DMG channels, including channel-1 sweep, pulse envelopes, wave RAM, LFSR noise, length counters, and NR50/NR51 routing. `verification/platform/video.c` now uses hardware OAM, WX-7 window positioning, and correct vertically-flipped 8x16 sprite tile selection.

The runtime implementation remains an integration scaffold, not a substitute
for proof-porting every assembly label below. Unresolved integration points are
marked `FIDELITY_BOUNDARY(name)` in C.

## Runtime memory model

The PC runtime keeps the 64 KiB CPU address space and adds bank-aware ROM/SRAM
backing storage. `verification/include/bank.h` synchronizes the `$4000-$7fff`
window when a composed port switches `hLoadedROMBank`/`rROMB`. Native proof
ports retain their fixed-memory ABI; the PC platform exercises the backing bus.

The current acceptance scope is the title flow, OakSpeech prefix, player-data
initialization, starter Potion insertion, special-warp preparation, the
`EnterMap`/`LoadMapData` prefix, and the first playable overworld frame with
player movement/collision and OAM refresh. Full naming, map-entry animation,
warp/script dispatch, and complete overworld fidelity remain separate
boundaries.

## Team A: exact intro orchestration

Port these labels as resumable, one-frame-at-a-time C routines. Do not encode their output as a pre-rendered movie.

| Function | Source | Required behavior |
| --- | --- | --- |
| `PlayIntro` | `engine/movie/intro.asm:8` | Top-level order, interruption result, fade, cleanup. |
| `PlayShootingStar` | `engine/movie/intro.asm:305` | Copyright delay, LCD transition, graphics loads, star animation, music handoff. |
| `PlayIntroScene` | `engine/movie/intro.asm:23` | Exact Gengar/Nidorino script and interruption windows. |
| `AnimateIntroNidorino` | `engine/movie/intro.asm:143` | Consume ROM coordinate pairs with five-frame waits. |
| `IntroMoveMon` | `engine/movie/intro.asm:235` | Two-pixel movement every two frames and carry propagation. |
| `IntroCopyTiles` | `engine/movie/intro.asm:272` | Compose the tile-ID-list predef, not only its destination pointer. |
| `CopyTileIDsFromList` | `engine/battle/animations.asm:2545` | Complete the existing partial port and preserve base-tile behavior. |
| `AnimateShootingStar` | `engine/movie/splash.asm:22` | Big star, logo flashes, six small-star waves. |
| `MoveDownSmallStars` | `engine/movie/splash.asm:122` | Reverse OAM traversal, palette toggle, interruption carry. |
| `CheckForUserInterruption` | `home/overworld.asm:2394` | Up+Select+B held or Start/A edge, over exactly C frames. |

Acceptance tests:

1. Record `(frame, SCX, BGP, OBP0, OBP1, shadow OAM[0..159], tilemap)` from the ROM and C runtime at every VBlank.
2. Compare without timing normalization from copyright frame 0 through the final intro fade.
3. Repeat with A pressed during the big star, each scripted wait, and title wait; the transition frame must match.

## Team B: title screen

| Function | Source | Status/action |
| --- | --- | --- |
| `PrepareTitleScreen` | `engine/movie/title.asm:5` | Missing orchestration port. |
| `DisplayTitleScreen` | `engine/movie/title.asm:28` | Missing resumable orchestration port. |
| `LoadTitleMonSprite` | `engine/movie/title.asm:397` | Existing port does not complete front-pic rendering. |
| `LoadFrontSpriteByMonIndex` | `home/picture.asm` | Complete the current continuation boundary. |
| `TitleScreenScrollInMon` | `engine/movie/title.asm:282` | Existing port must compose the far `TitleScroll` call. |
| `TitleScreenAnimateBallIfStarterOut` | `engine/movie/title2.asm:90` | Missing. |
| `TitleScreenPickNewMon` | `engine/movie/title.asm:271` | Missing random selection/load/scroll composition. |
| `ScrollTitleScreenGameVersion` | `engine/movie/title.asm:288` | Needs scanline-aware PPU scheduling at LY=64 and LY=d. |

The macOS title bounce already uses the ROM's exact signed deltas and counts. The title-version raster reveal remains marked `FIDELITY_BOUNDARY(scanline-title-version)` because the compositor currently samples one SCX value for the whole frame.

Acceptance test: compare frame hashes and title-mon species sequence for 2,000 frames using identical DIV/TIMA/random seed inputs.

## Team C: audio command engine

The APU is no longer the blocker. The missing layer is the ROM command interpreter that writes it. Port the complete Engine 1 call cluster from `audio/engine_1.asm`, preserving four-channel shared state and per-frame order:

- `Audio1_PlaySound`, `Audio1_UpdateMusic`, `Audio1_ApplyMusicAffects`, `Audio1_PlayNextNote`;
- `Audio1_sound_ret`, `Audio1_sound_call`, `Audio1_sound_loop`;
- `Audio1_note_type`, `Audio1_toggle_perfect_pitch`, `Audio1_vibrato`, `Audio1_pitch_slide`;
- `Audio1_duty_cycle`, `Audio1_tempo`, `Audio1_stereo_panning`, `Audio1_unknownmusic0xef`, `Audio1_duty_cycle_pattern`, `Audio1_volume`, `Audio1_execute_music`, `Audio1_octave`;
- `Audio1_sfx_note`, `Audio1_pitch_sweep`, `Audio1_note`, `Audio1_note_length`, `Audio1_note_pitch`;
- `Audio1_EnableChannelOutput`, `Audio1_ApplyDutyCycleAndSoundLength`, `Audio1_ApplyWavePatternAndFrequency`, `Audio1_SetSfxTempo`, `Audio1_ApplyFrequencyModifier`;
- `Audio1_GoBackOneCommandIfCry`, `Audio1_IsCry`, `Audio1_ApplyPitchSlide`, `Audio1_InitPitchSlideVars`, `Audio1_ApplyDutyCyclePattern`;
- `Audio1_GetNextMusicByte`, `Audio1_GetRegisterPointer`, `Audio1_MultiplyAdd`, `Audio1_CalculateFrequency`.

Then replace `intro_sound()` in `platform/game.c` with calls through the ported `PlaySound`/`PlayMusic` path. The required opening assets are `SFX_Shooting_Star`, `Music_IntroBattle`, all intro move SFX, `Music_TitleScreen`, cries, `Music_Routes2`, shrink SFX, and `Music_PalletTown`.

Acceptance test: log every write to NR10-NR52 and wave RAM from both implementations with cycle/frame stamps. Register traces must match before comparing PCM output.

## Team D: Oak speech and naming

The runtime now composes the ported OakSpeech prefix, `InitPlayerData2`,
`AddItemToInventory`, and `PrepareForSpecialWarp`. The naming screens and
remaining picture/audio choreography stay outside the frame-driven path.

Acceptance test: exercise the OakSpeech prefix, confirm the starter Potion and
special-warp state are initialized, and compare the resulting WRAM against the
ROM before map entry.

## Team E: first map load

The PC driver composes the available map-entry prefix in this order:

1. `PrepareForSpecialWarp`
2. `EnterMap`
3. `LoadMapData`
4. `LoadMapHeader`
5. `InitMapSprites`
6. `LoadMapSpriteTilePatterns`
7. `LoadTileBlockMap`
8. `LoadTilesetTilePatternData`
9. `LoadCurrentMapView`
10. `LoadPlayerSpriteGraphics`
11. `CheckForceBikeOrSurf`

Runtime ROM-window synchronization covers the bank switches used by these
ports. `EnterMap` is triggered by A/Start from the OakSpeech prefix.

Acceptance test: at map entry, compare the entire `$c000-$dfff` WRAM range,
VRAM, OAM, IO registers, current ROM bank, and first rendered frame against
the ROM.

## Team F: minimum interactive overworld loop

These are all required before claiming that the player is in a 1:1 interactive overworld:

- `OverworldLoop`, `OverworldLoopLessDelay`, `JoypadOverworld`, `RunMapScript`;
- `UpdatePlayerSprite`, `UpdateNPCSprite`, and a completed `UpdateSprites`;
- `CanWalkOntoTile`, `CollisionCheckOnLand`, `CollisionCheckOnWater`;
- `CheckWarpsNoCollision`, `CheckWarpsCollision`, `WarpFound2`, `CheckMapConnections`, `ExtraWarpCheck`;
- `IsSpriteOrSignInFrontOfPlayer`, `DisplayTextID`, `PrintText_NoCreatingTextBox`;
- `TryDoWildEncounter`, `NewBattle`, `SafariZoneCheck`, and poison/step bookkeeping called by `OverworldLoopLessDelay`;
- start-menu dispatch reached by Start, including a clean close back into the same loop;
- map-script dispatch for Red's House 2F and Red's House 1F.

The exhaustive dependencies and every other missing/partial function remain in `PORTING_BACKLOG.md`; this handoff intentionally stops at the first faithful, controllable overworld frame.

## Integration rules

- A function is not complete if it sets `*_called`, `dispatch_called`, or callback state instead of invoking the callee or yielding a resumable call request.
- Delay routines must yield frame-by-frame; consuming an abstract observation in a tight loop is acceptable for proofs but not runtime composition.
- Use only ROM assets and tables. Do not redraw screens, substitute fonts, approximate map data, or bypass naming/map initialization.
- Preserve register flags, bank state, HRAM shadows, and side effects needed by callers.
- Add each finished function to `verification/ports.toml`, add differential tests, regenerate `PORTING_BACKLOG.md`, and remove only the matching `FIDELITY_BOUNDARY` marker.
- A visual match is necessary but not sufficient. State and audio-register traces are the acceptance oracle.
