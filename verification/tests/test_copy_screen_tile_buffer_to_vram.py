from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "0e0621000011a0c3cdfc18cdaf202100061118c4cdfc18cdaf2021000c1190c4cdfc18c3af207ae0c2cddd1c7de0c37ce0c4"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_copy_screen_tile_buffer_to_vram_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "CopyScreenTileBufferToVRAM")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY