# Water meter enclosure hardware

- [`vesimittari_v1_3/`](vesimittari_v1_3/README.md): original v1.3 STL, FreeCAD,
  STEP, render, and validation exports.
- [`vesimittari_kotelo.FCMacro`](vesimittari_kotelo.FCMacro): parameterized FreeCAD
  generator, copied from the original design source. Its export directory has
  been made portable and points to ignored `generated/` output.
- **[English printing and assembly instructions](../docs/assembly.md)**.

The supplied CAD/STL files are unchanged from the original exports. Finnish
filenames and CAD labels are retained so they match the original design and
validation report. The original Finnish notes are included for reference.

FreeCAD auto-backups and redundant ZIP archives are not included. The source
macro was copied rather than moved because the original may be used by other
design revisions. No CAD regeneration or physical fit test was performed during
this import.

Run `python tests/test_hardware_assets.py` from the repository root to check
binary STL closure/dimensions, the 14-piece quantity total, FreeCAD archive
integrity, and macro syntax. This does not regenerate CAD or test physical fit.
