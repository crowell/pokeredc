from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "f0baf5afe0baf0b8e08b78e0b8ea00207be0c77ae0c87de0c97ce0ca79fe083010e0c6cdaf20f08b"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_copy_video_data_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "CopyVideoData")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY