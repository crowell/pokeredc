from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "e08bf0b8f5f08be0b8ea0020e5d5d5545de1cdb500d1e1f1e0b8ea0020c9"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_far_copy_data3_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "FarCopyData3")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY