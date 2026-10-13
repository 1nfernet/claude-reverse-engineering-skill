"""Regression tests for malformed Android binary XML handling."""
import importlib.util
import struct
from pathlib import Path


_SPEC = importlib.util.spec_from_file_location(
    "app_inspect", Path(__file__).parents[1] / "skills/reverse-engineering/scripts/app_inspect.py"
)
app_inspect = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(app_inspect)


def test_parse_axml_ignores_truncated_chunk_after_valid_header():
    """A declared chunk extending past EOF must not cause struct.error."""
    data = struct.pack("<HHI", 0x0003, 8, 16) + struct.pack("<HHI", 0x0102, 16, 20)
    assert list(app_inspect.parse_axml(data)) == []
