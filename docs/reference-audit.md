# Reference image and map audit

## Byte identity

| Asset | Bytes | SHA-256 |
| --- | ---: | --- |
| `ACTUAL TOOL/DEF/Original.bin` and `ACTUAL TOOL/Original.bin` | 1,572,864 each | `c4f37931b7ad760594f0bb16313278bc0b687e43e6e5aea3e48257e2c9f20361` |
| `ACTUAL TOOL/DEF/TESTED.xdf` | 273,178 | `3442e70e70b61c979e2dd1aa7baa43ea92da14737f260a8fe69e63a0276781e3` |

The reference image spans `[0x000000, 0x180000)`. The right endpoint is exclusive. Both BIN paths resolve to Git blob `35d3f134b30d9229bb7dcc6c0f2d4dce47ae9e24`. The check-only invocation in the root README was run against the reference. The two 16-bit fields and both 32-bit fields matched their calculated values.

| Field as named by the checker | Stored and calculated |
| --- | --- |
| Lower BE16 sum | `0x5889` |
| Upper BE16 sum | `0xA304` |
| BE32 XOR | `0x3E8D742B` |
| BE32 ADD | `0x7FC66CA1` |

## What the XDF describes

The XML declares XDF 1.80, a zero base offset, a region of `0x180000` bytes, and 57 categories. The title in the file is “G37 Starter Definition”. The [index](map-index.csv) retains the original titles and distinct object IDs, including repeated titles. One row represents one scalar, table value plane, or flag. Axis definitions, category memberships, labels and detailed metadata remain in the XDF.

| Object kind | Count | Missing value address |
| --- | ---: | ---: |
| Table | 101 | 1 |
| Constant | 88 | 8 |
| Flag | 8 | 4 |
| **Total** | **197** | **13** |

A blank address means the element lacks `mmedaddress`. Some labels mention a number while their address field is empty. Keep the offset unknown. The file contains four value equations that use lowercase `x`. Preserve their source text. For bit flags, retain the mask alongside the storage address. Two objects share the exact title `Rpm Fuel Restore` and three share `MON8200`; title-based lookup alone loses entries.

## Reproducible spot checks

These values come directly from the checked-in BIN and XDF using the stated encodings. They test offsets and scaling for this file pair.

| Object | File offset | Reference bytes | Result |
| --- | --- | --- | --- |
| Baro Pressure Sensor Char Coe, `0x30A6` | `0x88F0` | `70` | 112 / 32 = 3.5 |
| Fuel Cut Engine Speed Lower Limit, `0x307E`, first cell | `0x1469E` | `66` | 102 × 12.5 = 1,275 |
| VVEL duration vs angle, `0x1584` and `0x308C`, first cell of each | `0x15BE2`, `0x1B5EE` | `32 00` at both | Big-endian 12,800 / 512 = 25 |

These checks establish how the selected objects read on the reference. Several tables contain literal axis labels, and those labels can carry placeholders. Coverage and a plausible displayed value alone cannot validate physical units, axis calibration, or compatibility with another ROM.

To regenerate the CSV from the repository root, run the following with Python 3.

```shell
python tools/index_xdf.py > docs/map-index.csv
```
