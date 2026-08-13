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
