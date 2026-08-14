# Assembly-to-C equivalence verification

This directory contains the native-C ports and the angr-based equivalence
harness. The first vertical slice targets `StringCmp` from
`home/compare.asm`.

## Prerequisites

- RGBDS 1.0.3 (`rgbasm`, `rgblink`, and `rgbfix`) to build the original ROM
- Clang with an ELF-capable linker for the freestanding native-C side
- Python 3 with the packages in `requirements.txt`

The checked-out repository already records the required RGBDS version in
`.rgbds-version`.

## Build and test

From the repository root:

```sh
make verify
```

The assembly proof requires `pokered.gbc` and `pokered.sym`. The test suite
skips that proof with a clear reason when those artifacts are absent.

## Proof boundary

`StringCmp` is proved by an exhaustive one-iteration transition check over all
register, flag, pointer, counter, and byte-pair inputs. The transition includes
both return paths and the exact loop-back state. Because the assembly and C
then apply the same proved transition recursively, this establishes every
effective length from 1 through 256, including pointer equality and 16-bit
wraparound. Direct symbolic one- and two-byte checks remain as regression tests.

The original program runs through angr's P-code engine using the bundled
`z80:LE:16:default` language. This is not an SM83 language definition. Every
ported routine therefore needs a decoder-compatibility gate before a proof
using this backend can be accepted.

## Current proof ledger

`ports.toml` is the authoritative progress ledger. Its statuses mean:

- `partial`: the tested domain is equivalent, but some declared input domain
  remains.
- `proven`: the complete declared input domain and every listed observable
  have been checked for equivalence.

Current results:

- `StringCmp`: proven for arbitrary registers, flags, 16-bit pointers, all
  byte pairs, and every effective length from one through 256 by induction on
  the exhaustively checked loop transition.
- Twenty-seven map-script zero/reset leaves: proven across all registers,
  flags, and affected script bytes, with every linked body checked exactly.
- Additional dependency-free register, memory-transfer, hardware-palette,
  pointer-write, item-failure, and fade-entry routines are proven over their
  complete symbolic state; variable loops use audited one-step induction.
- `Sub5ClampTo0`: proven for every 8-bit accumulator input.
- `CalcDifference`: proven for every 8-bit accumulator/`B` input pair.
- `EmptyFunc` and `EmptyFunc3`: proven to preserve all general registers and
  canonical flags.
- `AIMoveChoiceModification4`: proven to preserve all general registers and
  canonical flags.
- `GenericAI`: proven across all initial registers and flags.
- `DecrementAICount`: proven across all registers, flags, and all 256 possible
  counter values.
- `CheckSumFailed` and `GoodCheckSum`: proven across all registers, flags, and
  both affected mapper-control register values.
- `EndLowHealthAlarm`: proven across all registers, flags, and its three
  affected global bytes.
- `CheckNumAttacksLeft`: proven across all registers, flags, both attack
  counters, both battle-status bytes, and all three terminal paths.
- `ClearHyperBeam`: proven across all registers, flags, turn values, both
  battle-status bytes, and both terminal paths.
- `HyperBeamEffect`: proven across all registers, flags, turn values, both
  battle-status bytes, and both terminal paths.
- `AnyPartyAlive`: proven across all registers, flags, twelve party HP bytes,
  and every legal party count from one through six.
- `AnyEnemyPokemonAliveCheck`: proven across all registers, flags, twelve
  enemy-party HP bytes, and every legal party count from one through six.
- `GetBattleTransitionID_WildOrTrainer`: proven across all registers, flags,
  and all 256 opponent IDs.
- `GetBattleTransitionID_CompareLevels`: proven for every possible first
  surviving party slot, arbitrary HP bytes, and legal player/enemy levels.
- `GetBattleTransitionID_IsDungeonMap`: proven across all registers, flags,
  all 256 map IDs, and both linked dungeon-map tables.
- `BattleTransition_BlackScreen`: proven across all registers, flags, and the
  three affected hardware palette registers.
- `UpdateHPBar_CompareNewHPToOldHP` and `UpdateHPBar_CalcHPDifference`: proven
  across all registers, flags, and every possible pair of 16-bit HP values.
- `QuarterSpeedDueToParalysis` and `HalveAttackDueToBurn`: proven across both
  combatants, every turn/status byte, and every pair of 16-bit stat values.
- All three `ApplyBurnAndParalysisPenalties*` entry points: proven compositionally
  across both statuses and all four affected 16-bit stats.
- `SlidePlayerHeadLeft`: proven across all registers, flags, and all 21 affected
  OAM X-coordinate bytes.
- `SwapPlayerAndEnemyLevels`: proven across all registers, flags, and both
  possible level bytes.
- `GetSubanimationTransform1` and `GetSubanimationTransform2`: proven across
  all registers, flags, and all turn-byte values.
- `IsCryMove`: proven across all registers, flags, and all 256 animation IDs.
- `GetMonSpriteTileMapPointerFromRowCount`: proven across all registers, flags,
  turn values, and every legal row count from one through seven.
- `GetTileIDList`: proven for every legal tilemap-list index with the complete
  linked pointer/dimension table checked byte-for-byte.
- `AnimCopyRowLeft` and `AnimCopyRowRight`: proven for both real caller counts
  with symbolic overlapping row data and all register/flag effects checked.
- `SetAnimationPalette`: proven across every SGB/animation/palette byte and all
  register and flag inputs.
- `FallingObjects_UpdateMovementByte`: proven across all 256 movement states,
  including both direction-changing wrap paths.
- `ShareMoveAnimations`: proven across every turn byte and animation ID.
- `FallingObjects_InitXCoords` and `FallingObjects_InitMovementData`: proven
  for both legal object counts with their complete linked tables and symbolic
  destination buffers.
- `FallingObjects_UpdateOAMEntry`: proven for all 20 legal OAM offsets, every
  movement byte, and the complete 128-byte ROM window reachable by its masked
  lookup index.
- `AdjustOAMBlockXPos`, `AdjustOAMBlockXPos2`, `AdjustOAMBlockYPos`, and
  `AdjustOAMBlockYPos2`: proven across all adjustment and OAM bytes for every
  caller count, including the Y routine's previous-entry attribute bug.
- `BattleAnimWriteOAMEntry`: proven across all register, base-coordinate, and
  four-byte destination OAM values.
- `Audio1_IsCry`, `Audio2_IsCry`, and `Audio3_IsCry`: proven independently
  across all sound IDs, registers, and flags.
- `Audio2_IsBattleSFX`: proven across every channel-5/channel-8 sound-ID pair.
- `Audio1_EnableChannelOutput`, `Audio2_EnableChannelOutput`, and
  `Audio3_EnableChannelOutput`: proven for all eight channels with symbolic
  hardware, stereo-panning, and corresponding-SFX state.
- `Audio1_MultiplyAdd`, `Audio2_MultiplyAdd`, and `Audio3_MultiplyAdd`: proven
  for every multiplier and symbolic remaining registers; duplicate variants
  are additionally gated as byte-identical on both architectures.
- `Audio1_GetRegisterPointer`, `Audio2_GetRegisterPointer`, and
  `Audio3_GetRegisterPointer`: proven for all eight channels and every register
  offset, including exact returned flags and hardware pointers.
- `Audio1_CalculateFrequency`, `Audio2_CalculateFrequency`, and
  `Audio3_CalculateFrequency`: proven directly for all 96 legal note/octave
  combinations per engine, including exact pitch-table pointer side effects.
- `Audio1_ApplyDutyCyclePattern`, `Audio2_ApplyDutyCyclePattern`, and
  `Audio3_ApplyDutyCyclePattern`: proven compositionally for all channels with
  symbolic software patterns and hardware duty registers.
- `Audio1_ApplyDutyCycleAndSoundLength`, `Audio2_ApplyDutyCycleAndSoundLength`,
  and `Audio3_ApplyDutyCycleAndSoundLength`: proven compositionally for all
  channels with symbolic note delays, duty cycles, and hardware duty registers.
- `Audio2_ResetCryModifiers`: proven across every channel, alarm, modifier,
  register, and flag value, including both alarm-bit paths on channel 5.
- `Audio1_SetSfxTempo`, `Audio2_SetSfxTempo`, and `Audio3_SetSfxTempo`: proven
  across all sound IDs and tempo modifiers with exact classifier side effects,
  output bytes, registers, and flags.
- `Audio1_ApplyFrequencyModifier`, `Audio2_ApplyFrequencyModifier`, and
  `Audio3_ApplyFrequencyModifier`: proven for every legal hardware-frequency
  pointer with symbolic sound IDs, modifiers, register pairs, and flags.
- `Audio1_ApplyWavePatternAndFrequency`, `Audio2_ApplyWavePatternAndFrequency`,
  and `Audio3_ApplyWavePatternAndFrequency`: proven for all channels and all
  nine defined wave instruments with complete linked wave data and symbolic
  wave RAM, frequency hardware, cry state, registers, and flags.
- `Audio1_GoBackOneCommandIfCry`, `Audio2_GoBackOneCommandIfCry`, and
  `Audio3_GoBackOneCommandIfCry`: proven for all channels, sound IDs, and
  16-bit command pointers, including borrow, wraparound, and final flags.
- `Audio1_GetNextMusicByte`, `Audio2_GetNextMusicByte`, and
  `Audio3_GetNextMusicByte`: proven for every channel and every pointer in the
  banked-ROM window with arbitrary fetched bytes and full pointer writeback.
- `Audio1_ApplyPitchSlide`, `Audio2_ApplyPitchSlide`, and
  `Audio3_ApplyPitchSlide`: proven for both directions and all channels with
  symbolic integer/fractional state, targets, flags, and frequency hardware.
- `Audio1_InitPitchSlideVars`, `Audio2_InitPitchSlideVars`, and
  `Audio3_InitPitchSlideVars`: proven for all channels and caller-valid
  frequencies/divisors, including both original borrow bugs and a formally
  validated repeated-subtraction loop summary.
- All three `execute_music` and `octave` command handlers: proven over every
  command/channel/state value with matched and fallthrough tail continuations
  represented and checked explicitly.
- All three `duty_cycle`, `stereo_panning`, `volume`, and
  `duty_cycle_pattern` command handlers: proven for every command/channel,
  banked pointer, fetched parameter, affected state byte, and tail continuation.
- All three `tempo` and `toggle_perfect_pitch` command handlers: proven for
  every command/channel and affected state, including both two-byte tempo
  branches, banked pointer writeback, and explicit fallthrough continuations.
- All three `vibrato` command handlers: proven for every command/channel,
  two-byte parameter pair, pointer writeback, and affected delay, extent, and
  rate byte, including the SM83-specific nibble-swap semantics.
- All three `pitch_sweep` handlers: proven for every channel, command,
  execute-music flag, banked pointer, fetched parameter, and sweep-register
  value across both distinct note fallthroughs and the successful command path.
- All three `pitch_slide` command handlers: proven for every channel, legal
  note/octave pair, three-byte parameter sequence, banked pointer, affected
  target-frequency state, and both decoder continuations.
- All three `note_type` handlers: proven for every command/channel, including
  the zero-parameter noise path, wave-instrument encoding paths, ordinary
  volume/fade paths, pointer writeback, and both decoder continuations.
- All three `sound_call` handlers: proven for every channel, target pointer,
  current pointer, return-address state, call flag, command value, and both
  decoder continuations.
- All three `sound_loop` handlers: proven for every channel, command pointer,
  target pointer, loop count, loop-counter state, and all four fallthrough,
  infinite, repeating, and completed path domains.
- All three `note_length` handlers: proven for every channel and legal encoded
  length with symbolic note speeds, tempo words, fractional delay state, flags,
  sound IDs, and tempo modifier; the native multiplication/addition leaf is
  independently proven over its complete factor domain.
- All three `note_pitch` handlers: proven for every channel across rests and all
  legal notes/octaves, music/SFX arbitration, hardware output, wave patterns,
  perfect pitch, frequency modifiers, and both pitch-slide domains.
- All three `PlayNextNote` callers: proven for every channel and affected
  vibrato/slide state up to the explicit `sound_ret` boundary, including
  Audio 2's low-health-alarm early return for channel 5.
- All three `sound_ret` handlers: proven across command fallthrough, recursive
  sound-call returns, music/SFX cleanup, hardware output shutdown, wave-channel
  restart, cry rewind, and saved-volume restoration paths.
- All three `sfx_note` handlers: proven for every channel across decoder
  fallthrough, execute-music rejection, two- and three-byte frequency forms,
  note-length composition, and all affected audio hardware and wave state.
- All three `ApplyMusicAffects` routines: proven for every channel across note
  scheduling, music/SFX arbitration, duty rotation, pitch-slide selection, and
  all vibrato delay/rate/direction and saturating-frequency paths.
- All three `UpdateMusic` loops: proven over all sound IDs and mute-state
  histories up to the explicit `ApplyMusicAffects` boundary or final return,
  including the channel-output shutdown/restart sequence.
- All three 672-byte `PlaySound` dispatchers: proven over every linked header
  topology with symbolic audio RAM, hardware, and incumbent sound arbitration,
  including music reset, SFX replacement, cries, `$fe`, and stop-all-audio.
- All three unused `unknownmusic0xef` handlers: proven for every channel and
  arbitrary `PlaySound` post-state, including both decoder fallthrough and
  post-call channel-8 cleanup paths.
- All three `note` dispatchers: proven across all channels and command nibbles,
  including short noise instruments, two-byte drum notes, output suppression,
  arbitrary `PlaySound` results, and explicit `note_length` fallthrough.
- `IsItemHM`: proven for every 8-bit item ID, including all returned flags.
- `EnableAutoTextBoxDrawing` and `DisableAutoTextBoxDrawing`: proven across all
  registers, flags, and both affected global bytes.
- `AutoTextBoxDrawingCommon`: proven across all registers, flags, and both affected global bytes; it stores the incoming accumulator into `wAutoTextBoxDrawingControl`, clears A (XOR A), and stores zero into `wDoNotWaitForButtonPressAfterDisplayingText`.
- `WaitLoop_15Iterations`: proven across all initial registers and flags.
- `InitOptions` and `DiscardButtonPresses`: proven across all registers, flags,
  and their affected global/HRAM bytes.
- `IsUnknownCounterZero` and `SetUnknownCounterToFFFF`: proven across all
  registers, flags, and both serial-counter bytes.
- `InitYesNoTextBoxParameters`: proven across all registers, flags, and its
  affected menu-state byte.
- `EmptySRAMBox`: proven for every writable two-byte SRAM location and all
  initial register, flag, and byte values.
- `ResetUsingStrengthOutOfBattleBit`: proven across all registers, flags, and
  status-byte values.
- `GetPlayerTeleportAnimFrameDelay`: proven across all registers, flags, and
  all 256 possible `wOnSGB` byte values.
- `RestoreFacingDirectionAndYScreenPos`: proven across all registers, flags,
  source bytes, and destination bytes.
- `IgnoreInputForHalfSecond`: proven across all registers, flags, and both
  affected global bytes.
- `HasEnoughCoins`: proven across every pair of 2-byte BCD values held in
  `wPlayerCoins` and `hCoins`; the routine loads DE/HL/C and delegates the
  byte-wise comparison to StringCmp, whose port is proven.
- `HasEnoughMoney`: proven across every pair of 3-byte BCD values held in
  `wPlayerMoney` and `hMoney`; identical structure with a length of three.
- `InGameTrade_GetReceivedMonPointer`: proven across all registers, flags,
  16-bit BC/HL pairs, and every `wPartyCount` byte; it loads the count,
  decrements it, runs the proven AddNTimes loop, and copies HL into DE.
- `SetPal_BattleBlack`: proven across all registers, flags, and the linked
  `PalPacket_Black` / `BlkPacket_Battle` addresses; selects a palette packet.
- `SetPal_TownMap`: proven across all registers, flags, and the linked
  `PalPacket_TownMap` / `BlkPacket_WholeScreen` addresses.
- `SetPal_PartyMenu`: proven across all registers, flags, and the linked
  `PalPacket_PartyMenu` / `wPartyMenuBlkPacket` addresses.
- `SetPal_Slots`: proven across all registers, flags, and the linked
  `PalPacket_Slots` / `BlkPacket_Slots` addresses.
- `SetPal_TitleScreen`: proven across all registers, flags, and the linked
  `PalPacket_Titlescreen` / `BlkPacket_Titlescreen` addresses.
- `SetPal_Generic`: proven across all registers, flags, and the linked
  `PalPacket_Generic` / `BlkPacket_WholeScreen` addresses.
- `SetPal_NidorinoIntro`: proven across all registers, flags, and the linked
  `PalPacket_NidorinoIntro` / `BlkPacket_NidorinoIntro` addresses.
- `SetPal_GameFreakIntro`: proven across all registers, flags, the linked
  `PalPacket_GameFreakIntro` / `BlkPacket_GameFreakIntro` addresses, and the
  `wDefaultPaletteCommand` byte written with SET_PAL_GENERIC ($08); the SM83
  absolute store is modeled explicitly.
- `PrintPlayerMon1Text`: proven across all registers, flags, and the linked
  `PlayerMon1Text` address; selects a text pointer.
- `PrintComeBackText`: proven across all registers, flags, and the linked
  `ComeBackText` address; selects a text pointer.
- `LoadPresentsGraphic`: proven across all registers and flags (body is a single
  RET, so every register and flag is preserved).
- `SafariZoneGameStillGoing`: proven across all registers, flags, and the
  `wSafariZoneGameOver` byte cleared to zero; the SM83 absolute store is modeled
  explicitly.
- `InGameTrade_CopyData`: proven across all registers, flags, and every symbolic
  source-buffer contents; it pushes HL and BC, delegates the byte-wise copy to the
  proven CopyData loop, and pops HL and BC back, so the destination receives the
  source verbatim while HL and BC are preserved.
- `SaveScreenTilesToBuffer2`: proven across all registers, flags, and every
  symbolic 360-byte (SCREEN_AREA) source buffer; it sets HL/DE/BC to the tile
  map, wTileMapBackup2 and SCREEN_AREA constants and delegates the byte-wise copy
  to the proven CopyData loop (HL/DE/BC are left mutated).
- `SaveScreenTilesToBuffer1`: proven across all registers, flags, and every
  symbolic 360-byte (SCREEN_AREA) source buffer; it sets HL/DE/BC to the tile
  map, wTileMapBackup and SCREEN_AREA constants and jumps (rather than calls)
  CopyData, which returns directly to the caller (HL/DE/BC are left mutated).
- `LoadScreenTilesFromBuffer1`: proven across all registers, flags, the
  `hAutoBGTransferEnabled` byte (written to 0 then 1), and every symbolic 360-byte
  source buffer; it sets HL/DE/BC to wTileMapBackup, the tile map and SCREEN_AREA
  and delegates the byte-wise copy to the proven CopyData loop.
- `LoadScreenTilesFromBuffer2DisableBGTransfer`: proven across all registers,
  flags, the `hAutoBGTransferEnabled` byte (written to 0), and every symbolic
  360-byte source buffer.
- `LoadScreenTilesFromBuffer2`: proven across all registers, flags, the
  `hAutoBGTransferEnabled` byte (written to 1 at the end), and every symbolic
  360-byte source buffer; it runs LoadScreenTilesFromBuffer2DisableBGTransfer and
  then re-enables the auto BG transfer.
- `AnimCutGrass_SwapOAMEntries`: proven across all registers, flags, and every symbolic 8-byte source OAM buffer; it sets HL/DE/BC to each shadow-OAM sprite pair and delegates the byte-wise copy to the proven CopyData loop (two calls and one tail jump), so the two sprite entries are swapped with HL/DE/BC left mutated.
- `ClearVariablesOnEnterMap`: proven across all registers, flags, and every affected global/HRAM byte (hWY, rWY, hAutoBGTransferEnabled, wStepCounter, wLoneAttackNo, hJoyPressed/Released/Held, wActionResultOrTookBattleTurn, wUnusedMapVariable, the wCardKeyDoorY pair, and the zeroed FillMemory span from wWhichTrade through wStandingOnWarpPadOrHole); it sets HL/BC and delegates the span zeroing to the proven FillMemory loop.
- `MovePicLeft`: proven across all registers, flags, and the affected `rWX`/`rBGP` hardware bytes; it steps rWX down by 8 from 119 to 7 and returns with A=0xFF/F=N|Z once the scroll reaches zero, looping with a DelayFrame call between steps.
- `ResetPlayerSpriteData_ClearSpriteData`: proven across all registers, flags, and the symbolic 16-byte (`SPRITESTATEDATA1_LENGTH`) sprite-state region; it sets BC=16 and A=0 and delegates the zero-fill to the proven FillMemory loop, which advances HL by 16 and leaves A=0/F=Z/BC=0.
- `UnusedPlayerNameLengthFunc`: proven across all registers, flags, and the symbolic 11-byte `wPlayerName` buffer; it scans from `wPlayerName` until the `@` ($50) text terminator and leaves `BC = -(name length)` (B=$ff, C decremented once per non-terminator byte), returning with A=`@` and F=N|Z; the loop runs natively under the pcode engine with no SM83 shims.
- `GetQuantityOfItemInBag`: proven across all registers, flags, and the symbolic `wNumBagItems` item table; given `b` = an item ID it scans id/quantity pairs from `wNumBagItems` until the `$ff` terminator or a matching id, returning with `b` = the matched quantity (or 0 if absent), `a` = the matched id, and `F=N|Z`; `call GetPredefRegisters` is skipped (b passes through, hl overwritten), `ld a,[hli]` (0x2A) and the `cp $ff`/`cp b` comparisons are shimmed for SM83 semantics, and the loop control runs natively.
- `HoFFadeOutScreenAndMusic`: proven across all registers, flags, and the three audio-fade control bytes (`wAudioFadeOutControl`=$ff, `wAudioFadeOutCounterReloadValue`/`wAudioFadeOutCounter`=10); it writes those bytes and transfers to `GBFadeOutToWhite`, modeled here as the endpoint, with the three SM83 EA absolute stores shimmed.
- `HoFRecordMonInfo`: proven across all registers, flags, and the symbolic inputs `wHoFPartyMonIndex` (slot), `wHoFMonSpecies`, `wHoFMonLevel`, and the 11-byte `wNameBuffer`; it writes a 13-byte record (species, level, name) at the data-dependent address `wHallOfFame + HOF_MON * wHoFPartyMonIndex`, with `call AddNTimes` modeled as `hl = hl + bc*a`, the `ld a,[a16]`/`ld [hli],a` opcodes shimmed, and the `jp CopyData` tail inlined to copy the name; the post-CopyData registers are scratch and excluded from the observable record.
- `KnowsHMMove`: proven for observable `A` across all general-register and canonical-flag inputs; with the mon index `[wWhichPokemon]` fixed concrete (1) the move-list base `wPartyMon1Moves + PARTYMON_STRUCT_LENGTH * which` is concrete while the four party moves stay symbolic and shared between the asm and native paths. The function walks the move list with `AddNTimes` (`hl = hl + bc*a`, a=0 leaves hl unchanged) and `ld a,[hli]` (0x2A) shimmed, and inlines `IsInArray` as an `IsInArraySim` that sets the z80 carry iff `a` is one of the five HM ids; it returns the first matching HM move id (carry set) or, on no match, the last move read (the `and a; ret` tail does not zero `a`).
- `DecrementPP`: proven for the two observable PP bytes (`m_battle_pp` at `wBattleMonPP + moveIndex`, `m_party_pp` at `wPartyMon1PP + PARTYMON_STRUCT_LENGTH * which + moveIndex`) across all general-register and canonical-flag inputs; the used move id (read from `[de]`) and the three battle-status bytes (`wPlayerBattleStatus1/2/3`) stay symbolic while the move index and party-mon number are fixed concrete so the PP addresses are concrete. The function has five terminal paths — Struggle, a `wPlayerBattleStatus1` status mask, or Rage early-exit (no writes), a battle-only decrement when transformed, and a full double decrement — all matched by the native C; `ld a,[hli]` (0x2A) and the three `ld a,[a16]` (0xFA) loads are shimmed, `call AddNTimes` is modeled as `hl = hl + bc*a`, and the internal `call .DecrementPP` plus `dec [hl]`/`bit`/`and`/`cp`/conditional returns run natively under the pcode engine.
- `IncrementMovePP`: proven for the four observable PP bytes (`m_player_battle_pp` at `wBattleMonPP + moveIndex`, `m_player_party_pp` at `wPartyMon1PP + PARTYMON_STRUCT_LENGTH * which + moveIndex`, `m_enemy_battle_pp` at `wEnemyMonPP + moveIndex`, `m_enemy_party_pp` at `wEnemyMon1PP + PARTYMON_STRUCT_LENGTH * which + moveIndex`) across all general-register and canonical-flag inputs; `hWhoseTurn` (player/enemy selector) and the move index / party-mon number are fixed concrete so every PP address is concrete while the four initial PP bytes stay symbolic and shared between the asm and native paths. The proof is run once per turn (whose = 0 player, 1 enemy) so both player and enemy branches are covered; the two `ldh a,[a8]` (0xF0) and four `ld a,[a16]` (0xFA) loads are shimmed, and `call AddNTimes` is modeled as `hl = hl + bc*a` (a=0 leaves hl unchanged), with `inc [hl]` running natively.
- `AICureStatus`: proven for the three observable bytes (`m_roster` at `wEnemyMon1Status + PARTYMON_STRUCT_LENGTH * partyPos`, `m_active` at `wEnemyMonStatus`, `m_battle3` at `wEnemyBattleStatus3` with the BADLY_POISONED bit cleared) across all general-register and canonical-flag inputs; `wEnemyMonPartyPos` is fixed concrete (0) so the roster status address is concrete while the roster status, active status, and `wEnemyBattleStatus3` bytes stay symbolic and shared between the asm and native paths. The `ld a,[a16]` (0xFA) and `ld [a16],a` (0xEA) opcodes are shimmed, `res BADLY_POISONED,[hl]` (0xCB 0x86) is shimmed, and `call AddNTimes` is modeled as `hl = hl + bc*a` (a=0 leaves hl unchanged), with `xor a`, `ld [hl],a`, and `ret` running natively.
- `ReadMove`: proven for the six observable move-data bytes (`m_move0..m_move5` at `wEnemyMoveNum`) across all general-register and canonical-flag inputs; the 1-based move id in A is fixed concrete (1 → index 0) so the Moves-table source address is concrete while the six move-data bytes stay symbolic and shared between the asm and native paths. `call AddNTimes` is modeled as `hl = hl + bc*a` (a=0 leaves hl unchanged) and `call CopyData` is modeled as a BC-byte copy from `[HL]` to `[DE]` (CopyDataSim); `ld hl,nn`/`ld bc,nn`/`ld de,nn`/`dec a`/push/pop/`ret` run natively.
- `GetMonName`: proven for the eleven observable name bytes (`m_name0..m_name9` at `wNameBuffer`, `m_terminator` = `$50` text terminator at `wNameBuffer + NAME_LENGTH - 1`) across all general-register and canonical-flag inputs; the 1-based species id in `[wNamedObjectIndex]` is fixed concrete (1 → index 0) so the MonsterNames source address is concrete while the ten name-data bytes stay symbolic and shared between the asm and native paths. `call AddNTimes` is modeled as `hl = hl + bc*a` and `call CopyData` is modeled as a BC-byte copy from `[HL]` to `[DE]` (CopyDataSim); the `ldh a,[a8]`/`ldh [a8],a` (0xF0/0xE0) and `ld [a16],a`/`ld a,[a16]` (0xEA/0xFA) opcodes are shimmed (the ROM-bank switch to MonsterNames is a no-op for the observable), and `ld hl,nn`/`ld bc,nn`/`ld de,nn`/`ld a,imm`/`ld c,imm`/`ld b,imm`/`dec a`/`ld [hl],imm`/push/pop/`ret` run natively.
- `SpinPlayerSprite`: proven for the five observable bytes (`m_image` = `wSpritePlayerStateData1ImageIndex` = `[HL]` at entry, `m_flist0..m_flist3` = `wFacingDirectionList[0..3]` after the rotate) across all general-register and canonical-flag inputs; the HL input pointer is fixed concrete (0xC600) so the store/copy addresses are concrete while the image-index source byte and the four facing-list entries stay symbolic and shared between the asm and native paths. `call CopyData` is modeled as a BC-byte forward copy from `[HL]` to `[DE]` (CopyDataSim), which rotates the list down by one entry; `ld [a16],a` (0xEA, writing `wSpritePlayerStateData1ImageIndex` and `wFacingDirectionList+3`) and `ld a,[a16]` (0xFA, reading the rotated former-first entry) are shimmed (absent from z80), and `ld a,[hl]`/`push hl`/`ld hl,nn`/`ld de,nn`/`ld bc,nn`/`pop hl`/`ret` run natively.
- `HallOfFame_Copy`: proven for the HOF_TEAM (PARTY_LENGTH*HOF_MON = 0x60) copied bytes (`m_copy` = the saved team written to `wHallOfFame`) across all general-register and canonical-flag inputs; HL (source slot), DE (=wHallOfFame) and BC (=HOF_TEAM) are fixed concrete so the copy addresses and length are concrete while the HOF_TEAM source bytes stay symbolic and shared between the asm and native paths. `call CopyData` is modeled as a BC-byte forward copy from `[HL]` to `[DE]` (CopyDataSim); the SRAM enable/disable `ld [a16],a` (0xEA, writing rRAMG/rBMODE/rRAMB) are shimmed (no-op for the observable in the flat memory model) and `ld a,imm`/xor a/`ret` run natively.
- `TradeCenter_PlaceSelectedEnemyMonMenuCursor`: proven for the single observable byte (`m_cursor` = the `▷` = `$ec` glyph written at `wTileMap + 1 + 9*SCREEN_WIDTH + row*SCREEN_WIDTH`) across all general-register and canonical-flag inputs; the selected row read from `[wSerialSyncAndExchangeNybbleReceiveData]` is fixed concrete (rows 0..5, covering the six party slots, each run as a separate equivalence check) so the tilemap store address is concrete. `ld a,[a16]` (0xFA, reading the row) is shimmed, `call AddNTimes` is modeled as `hl = hl + bc*a` (bc = SCREEN_WIDTH), and `ld hl,nn`/`ld bc,nn`/`ld [hl],imm` (0x36, writing `$ec`)/`ret` run natively.
- `FarCopyData`: proven for the BC (0x60) copied bytes (`m_copy` = the data written from `[HL]` to `[DE]`) across all general-register and canonical-flag inputs; HL (source), DE (dest) and BC (length) are fixed concrete so the copy addresses and length are concrete while the BC source bytes stay symbolic and shared between the asm and native paths (the A source-bank byte is unconstrained and only drives the no-op bank switch). `call CopyData` is modeled as a BC-byte forward copy from `[HL]` to `[DE]` (CopyDataSim); the bank switch `ld [a16],a` (0xEA, writing wBuffer/rROMB), `ld a,[a16]` (0xFA, reloading wBuffer), and `ldh a,[a8]`/`ldh [a8],a` (0xF0/0xE0, on hLoadedROMBank) are shimmed (no-op for the observable in the flat memory model), and `push af`/`pop af`/`ret` run natively.
