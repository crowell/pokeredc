# REQUIRED — unported functions hit by the macOS game-flow driver

`platform/game.c` composes the real boot flow (title screen → main menu →
new game) exclusively from functions already ported in `verification/ports/`.
Every asm label the driver needs but that has **no port yet** is listed here,
grouped by the screen that gates it. Driver call sites carry a matching
`/* REQUIRED: <label> */` comment (inlined approximations are marked).

Ports are added by translating the asm into `verification/ports/<name>.c`
following the existing conventions (state struct + flat `memory`, see
`verification/ports.toml` for the authoritative ledger). Once a function is
ported, delete its row here and replace the driver's approximation/comment
with the real call.

## Legend

- **gates** = what becomes visible/interactive once this exists
- *(inlined)* = driver currently fakes it with a trivial memory/hardware op

## Title screen — `DisplayTitleScreen` (engine/movie/title.asm)

| asm label | defined at | gates |
|---|---|---|
| `GBPalWhiteOut` | home/palettes.asm | palette fade-in on title appearance *(inlined: BGP/OBPx := $FF)* |
| `EnableLCD` / `DisableLCD` tail commit | home/lcd.asm | LCD toggle around tile uploads *(inlined: rLCDC write; `port_disable_lcd` covers flag semantics)* |
| `SaveScreenTilesToBuffer2` | home/window.asm | screen buffer swap before logo draw *(inlined memcpy wTileMap↔wTileMapBackup $C508)* |
| `LoadScreenTilesFromBuffer1/2` | home/window.asm | same swap-back *(inlined memcpy)* |
| ~~`DrawPlayerCharacter`~~ | engine/movie/title.asm | **PORTED & composed** (`port_draw_player_character`; host mirrors `state->sprites.oam[]` into wShadowOAM) |
| `LoadTitleMonSprite` | engine/movie/title.asm | starter mon picture shown on logo |
| ~~`ScrollTitleScreenPokemonLogo`~~ | engine/movie/title.asm | **PORTED** (`port_scroll_title_screen_pokemon_logo`) - consumes all DelayFrames in one call; driver keeps frame-paced hSCY until pacing is host-driven |
| ~~`ScrollTitleScreenGameVersion`~~ | engine/movie/title2.asm | **PORTED** (`port_scroll_title_screen_game_version`, takes observed LY/SCX arrays) - not yet wired into the driver |
| `TitleScreenScrollInMon` | engine/movie/title2.asm | mon slide-in after scroll |

## Main menu — `MainMenu` (engine/menus/main_menu.asm)

Composed via `port_main_menu_private` (head through save-file dispatch),
`port_start_new_game` (status-flag reset), `port_handle_menu_input_`,
`port_text_box_border`, `port_place_string`. Remaining gaps:

| asm label | defined at | gates |
|---|---|---|
| `TryLoadSaveFile` | home/sram.asm (predef) | CONTINUE path |
| `RunDefaultPaletteCommand` | engine/gfx/palettes.asm | SGB/GBC palettes (no-op on DMG renderer) |
| `UpdateSprites` | home/update_sprites.asm | sprite enable bit handling |
| `DisplayOptionMenu`, `DisplayContinueGameInfo` | engine/menus/*.asm | OPTION item, save-file continue screen |
| `PlaceMenuCursor` integration | home/menu.asm | port exists (`port_place_menu_cursor`, proven); driver still writes the $ED glyph inline pending wMenuCursorLocation plumbing |

Ported and available for deeper composition: `port_scroll_title_screen_game_version`
(scanline LY/SCX arrays), `port_title_scroll`, `port_get_title_ball_y`.

## New game intro — `OakSpeech` (engine/movie/oak_speech/oak_speech.asm)


| asm label | defined at | gates |
|---|---|---|
| `TextCommandProcessor` | home/text.asm | **all real dialogue rendering** (control codes <PKMN>/scroll/prompt). Driver falls back to raw `PlaceString` of ROM strings |
| `DisplayTextBoxID_` / MESSAGE_BOX template | home/textbox.asm + engine/text_box.asm | standard message-box layout (driver draws border+text manually). Composable pieces exist: `port_search_text_box_table`, `port_get_text_box_id_coords`, two-option-menu tile savers |
| `InitPlayerData2` | oak_speech/init_player_data.asm | party/inventory for a new file |
| ~~`GetMonHeader`~~ / ~~`FadeInIntroPic`~~ | home/pokemon.asm, engine/movie/intro.asm | **PORTED & composed** (`port_get_mon_header` with A=Nidorino/$A7; `port_fade_in_intro_pic` six-step BGP fade) |
| `IntroDisplayPicCenteredOrUpperRight`, `FadeInIntroPic`, `GBFadeOutToWhite`, `GBFadeInFromWhite` | engine/movie/intro.asm, home/fade.asm | Oak/Nidorino pictures and fades |
| `GetMonHeader`, `LoadFlippedFrontSpriteByMonIndex` | home/pokemon.asm, home/pics.asm | Nidorino battle pic |
| `ChoosePlayerName` / `ChooseRivalName` / naming screen | engine/menus/naming_screen.asm | naming screens (`port_choose_player_name_done`, `port_ask_name_declined_nickname`, `port_calc_string_length`, `port_load_ed_tile` are ported tails) |
| `PlayMusic` (Music_OakSpeech) | audio/ | intro theme |

Text-engine progress toward `TextCommandProcessor`: `TextCommand_PAUSE`,
`TextCommand_SCROLL`, `PrintLetterDelay`, `ScrollTextUpOneLine`,
`PrintBCDDigit`/`PrintBCDNumber`, and the `Joypad` homecall wrapper are
now ported.

Ported fragments ready to compose once the drivers above exist:
`port_move_pic_left`, `port_oak_speech_slide_pic_right`,
`port_get_default_name_found_name`, `port_give_pokemon`,
`port_oaks_lab_mon_choice_end`, `port_starter_dex_private`.

## Overworld — future phase (walking around)

Per coverage scan: `OverworldLoop`, `EnterMap`, `EnterMapAnim`,
`CheckWarpsNoCollision*` family, `CheckTilePassable` /
`CollisionCheckOnLand/OnWater/JoypadOverworld`,
`IsPlayerStandingOnDoorTileOrWarpTile`, `UpdateSprites`, `PrepareOAMData`
(sprite DMA processing), full-body `TryDoWildEncounter`. Ported and ready
to compose once those exist: `AdvancePlayerSprite`, `LoadCurrentMapView`,
`ReloadMapData`, `ReloadTilesetTilePatterns`,
`Schedule{North,South}Row/{East,West}ColumnRedraw`,
`RedrawRowOrColumn`, `AutoBgMapTransfer`, `IsPlayerStandingOnWarp`,
`GetTileSpriteStandsOn`, joypad suite.

## Battle — future phase

Post-merge (upstream `ds4`), now **proven** and ready to compose:
`PlayApplyingAttackSound`, `CopyTempPicToMonPic`, `CopyMonsterSpriteData`,
`AnimationShowMonPic` / `AnimationHideMonPic` /
`ClearMonPicFromTileMap`, the full shake-screen family
(`AnimationShakeScreen*`, `ShakeScreenVertically`,
`ShakeScreenHorizontally{Heavy,Light,Fast,Slow,Slow2}`),
`ScaleSpriteByTwo` + column scalers, `LoadHudTilePatterns`,
`LoadHudAndHpBarAndStatusTilePatterns`, `LoadPartyPokeballGfx`,
`LoadBattleTransitionTile`, and complete `CopyVideoData` /
`CopyVideoDataDouble` semantics.

Remaining blockers: `BattleCore` (whole file); partial entries for
`MainInBattleLoop`, `ExecutePlayerMove/EnemyMove`, `CalculateDamage`,
`CriticalHitTest`, `MoveHitTest`, `DisplayBattleMenu`,
`MoveSelectionMenu`; faint/end-of-battle handlers; the dialogue chain
(`TextCommandProcessor`) above; and the audio engine.
