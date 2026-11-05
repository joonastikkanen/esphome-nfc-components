"""Check supplied CAD archives/STLs without regenerating geometry or using FreeCAD."""
import ast
from collections import Counter
import json
from pathlib import Path
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]
HARDWARE = ROOT / "hardware/vesimittari_v1_3"
report = json.loads((HARDWARE / "tarkistus.json").read_text())
assert report["revision"] == "1.3"
assert len(report["parts"]) == 9
assert sum(part["quantity"] for part in report["parts"]) == 14
assert {path.stem for path in (HARDWARE / "stl").glob("*.stl")} == {
    part["name"] for part in report["parts"]
}

for part in report["parts"]:
    path = HARDWARE / "stl" / (part["name"] + ".stl")
    data = path.read_bytes()
    assert len(data) >= 84, path.name
    triangles = struct.unpack_from("<I", data, 80)[0]
    assert len(data) == 84 + 50 * triangles and triangles > 0, path.name
    vertices = []
    edges = Counter()
    for index in range(triangles):
        values = struct.unpack_from("<12fH", data, 84 + 50 * index)
        points = [tuple(round(value, 6) for value in values[start:start + 3]) for start in (3, 6, 9)]
        assert len(set(points)) == 3, f"Degenerate face: {path.name}"
        vertices.extend(points)
        for start in range(3):
            edges[tuple(sorted((points[start], points[(start + 1) % 3])))] += 1
    assert all(count == 2 for count in edges.values()), f"Open/non-manifold edges: {path.name}"
    dimensions = [max(v[axis] for v in vertices) - min(v[axis] for v in vertices) for axis in range(3)]
    assert all(abs(actual - expected) < .06 for actual, expected in zip(dimensions, part["size_mm"])), (
        path.name, dimensions, part["size_mm"]
    )
    print(f"{path.name}: {triangles} triangles; closed mesh; dimensions match report")

for name in ("Vesimittari_NFC.FCStd", "Tulostusosat.FCStd", "Havainne.FCStd"):
    with zipfile.ZipFile(HARDWARE / name) as archive:
        assert archive.testzip() is None, name
        assert "Document.xml" in archive.namelist(), name

assert (HARDWARE / "Vesimittari_NFC.step").read_bytes().startswith(b"ISO-10303-21;")
for path in HARDWARE.glob("*.png"):
    assert path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"), path.name
ast.parse((ROOT / "hardware/vesimittari_kotelo.FCMacro").read_text())
print("9 STL types / 14 printed pieces, 3 FreeCAD archives, STEP, renders, and macro syntax checked")
print("These checks do not establish physical fit, print strength, or RF performance")
