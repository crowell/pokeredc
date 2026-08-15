from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "f0b8f5f0b4cb47282c3e11ea0020e0b8cda069f0eea72010fa3ecdea0020e0b811da3ed5e9af180f060321507bcdd635f0db"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_check_for_hidden_event_or_bookshelf_or_card_key_door_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "CheckForHiddenEventOrBookshelfOrCardKeyDoor")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY