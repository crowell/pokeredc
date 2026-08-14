from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "faefc047fe022005210351180cfe08200521795818032177510e06c5e5cdd635e1c10d20f6c9"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_update_music_6_times_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "UpdateMusic6Times")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY