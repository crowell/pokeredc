from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "f0baf5afe0baf0b8e08b78e0b8ea00207be0cc7ae0cd7de0ce7ce0cf79fe083010e0cbcdaf20f08be0b8ea0020f1e0bac93e08e0cbcdaf2079d6084f18de3e7f111400e5c5220d20fcc1e1190520f4c9"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_copy_video_data_double_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "CopyVideoDataDouble")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY