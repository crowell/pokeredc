from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "fac7cfa7200bfa2cd7cb4fc03e77e024c9fac9cfa728053deac9cfc9fac8cfeac9cff024a7281147e60f3d4f78e6f0cb373dcb37b1e024c9fac7cf47afeac7cf3effeaeec0cdb123faf0c0eaefc078eaeec0c3b123f0b8f50601219670cdd6352111cfcb"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_fade_out_audio_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "FadeOutAudio")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY