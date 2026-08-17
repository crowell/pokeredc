from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "fa00d7a72819fe0228043ed218023ed6477aa73e1f2003eaefc0eaf0c01809fa5bd347"
    "cd85233805facacfb8c879eac7cf78eacacfeaeec0c3b123faefc047fe022005210351"
    "180cfe08200521795818032177510e06c5e5cdd635e1c10d20f6c9fa5cd35ffaefc0bb"
    "2005eaf0c0a7c979a77b2003eaefc0eaf0c037c9"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_play_default_music_common_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "PlayDefaultMusicCommon")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
