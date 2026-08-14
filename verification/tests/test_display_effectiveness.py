from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "fa5bd0e67ffe0ac8218e7b300321937bc3493c"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_display_effectiveness_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "DisplayEffectiveness")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY