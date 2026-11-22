# Offline implementation validation

Tool version: `g37offline 1.0.0`. Python 3.12. Implementation base: cleanup commit `99229fea9e6e6f81d528ebef2906203de321dd04` on `cleanup/offline-capture-handoff`, with the historical release at `c237843ce6c8a0202a056852c62961124f408bc6`. The change adds files only. All original tracked Git blob identities and the original archive ZIP are unchanged.

The supplied archive ZIP SHA-256 is `fd75ea788d7dea642eea7db00c8cd5cfd99d3f1f782b59e4d072be02fc8771a2`. All 54 entries in its `SHA256SUMS.txt` verify. Sources were unpacked outside the checkout; no captured data, private firmware fixtures or historical protected payloads were added to Git. Public test captures are independently invented synthetic bytes.

## Reproduced evidence

| Check | Observed result |
| --- | --- |
| Response-frame read import | 249,661 raw frames; 24,967 complete diagnostic messages; 24,967 data records. |
| Firmware data lengths | 24,966 records of 63 bytes; one of six bytes. |
| Full captured coverage | `[0, 0x180000)`, 1,572,864 bytes; zero missing/conflicting bytes; no base/fill bytes. |
| Reconstructed SHA-256 | `c4f37931b7ad760594f0bb16313278bc0b687e43e6e5aea3e48257e2c9f20361`, equal to the public reference and independent normalized-segment import. |
| Final six bytes | Reassembled from the captured single frame and linked to the address sidecar's final request/source lines. Not appended as padding. |
| Historical short output | 1,572,858-byte exact prefix; missing final six bytes. |
| Compact/spaced real tail | Eleven frames, same 69 recovered data bytes. Varied synthetic tail also matches. Removing the final frame leaves precisely six missing bytes in the requested range. Fully observed export is refused. |
| Full envelope inventory | 12,028 ordinary records + one terminal; claimed `[0x8200, 0x180000)`, 1,539,584 bytes; zero different ordinary envelopes between stored raw/message hashes. |
| Partial envelope inventory | 764 ordinary records + one terminal; claimed `[0x8200, 0x20000)`, 97,792 bytes; exactly three different ordinary envelopes. |
| Encoded inventory firmware claim | Zero recovered bytes from hashes or encoded bodies. Terminal claims zero bytes. |
| Archived decoded interval | SHA `822ebf4b44d8af3929205e58419997af7c19214287020c48dd30decbe88a3774`; every byte equals the reference slice at ROM 0x8200. Prefix remains missing. |
| Corrupted decoded association | Wrong inventory hash, variant, capture hash, capture-evidence hash, offset or decoded digest rejects import. |
| Definition index | 101 tables, 88 constants, 8 flags, 57 categories; 13 unresolved addresses; duplicate titles retained. |
| Historical exact pair | 727 changed bytes in 308 runs from 0x8200; older XDF covers 715; TESTED covers 717, with ten remaining checksum bytes. |
| Historical test2 vs repository reference | 9,299 differing bytes; test2 passes one checksum; padded comparison image passes four. |
| GUI/headless agreement | The normal Tk file-selection, analysis, map-selection and export callbacks produce identical `observed.bin` and `report.json` to the headless engine on the response-frame evidence. |

The historical comparison pair is exactly `historical/maps/comparison-fixtures/test2.bin` (SHA `da702a5cd66fc5e068780c64a7805610dbd2b5e80a8b1073a4096eccb348b3ce`) and `bintest1_decoded_sparse_0x008200_0x180000_PAD_BASE_0x8200_SIZE_0x180000(1).bin` (SHA `e079d1f13aa64ba090a8bf0c66137fa77323e6f5e3f2dac18538ecec181cf3b0`).

## Map and checksum anchors

| ROM offset | Raw / displayed result |
| --- | --- |
| `0x88F0` on repository reference | `70` → 3.5 |
| `0x1469E` on repository reference | `66` → 1,275 |
| `0x15BE2`, `0x1B5EE` on reference | Big-endian `32 00`, X/512 → 25 |
| `0x92B2` on reference | Big-endian `25 80` → 9,600 raw → 7,500 RPM with literal lowercase `x*25/32` |
| `0x1B604` historical pair | `91 E7` → `64 00`, 72.951171875 → 50 |
| `0xA3F0` historical pair | `D4` → `54`, both display 20; raw change remains reported |
| `0x1469E` historical pair | `14` → `A0`, 250 → 2,000 |

| Reference checksum | Stored | Calculated | Result |
| --- | --- | --- | --- |
| Lower BE16 at 0x8200 | 0x5889 | 0x5889 | Pass |
| Upper BE16 at 0x20000 | 0xA304 | 0xA304 | Pass |
| XOR32 at 0x95F0 | 0x3E8D742B | 0x3E8D742B | Pass |
| ADD32 at 0x95F8 | 0x7FC66CA1 | 0x7FC66CA1 | Pass |

A one-byte mutation fails the affected checks. A partial lower-range view calculates the lower check and marks the unavailable three checks individually. Cross-boundary partial cells remain unavailable rather than becoming zero.

## Commands and scope

Run from the repository root:

```shell
python -m g37offline ../G37_Historical_Archive/historical/fixtures/read-data-responses.log --sidecar ../G37_Historical_Archive/historical/fixtures/read-segments.csv --mode observed --xdf "ACTUAL TOOL/DEF/TESTED.xdf" --compare "ACTUAL TOOL/DEF/Original.bin" --output ../g37-results/read
G37_EVIDENCE=/absolute/path/G37_Historical_Archive python -m unittest discover -s tests -v
python "ACTUAL TOOL/g37_vq37_checksum_gui.py" --check "ACTUAL TOOL/DEF/Original.bin"
```

The suite contains 35 tests. With the real archive and a Tk display, all 35 run. Without a display, the GUI test is explicitly skipped; without the archive, five real-evidence tests are explicitly skipped. GUI verification used an isolated local Xorg dummy display and normal Tk widget callbacks, with file-picker responses supplied by the integration harness. It did not exercise a manual Windows desktop session. The suite was also run from a clean Git checkout. The existing map-index generator reproduces its checked-in CSV byte for byte, and the standalone check-only command passes.

Negative tests include bad DLC/hex, unsupported CAN FD, truncation, orphan/wrong-sequence frames, sequence wrap, interruptions, interleaved channels/directions/sessions, immediate repeated/conflicting frames, negative replies, outstanding requests, shuffled addresses, ambiguous/unsupported formats, same-address duplicate/conflicting segments, bounds, unequal file tails, altered sidecar data, stale input changes, output collisions and cancelled staging. Formula tests reject calls, attributes, external variables, nonfinite results and divide-by-zero while supporting both variable cases and trimming masks.

Historical functions were reviewed against `historical/python/provenance.json`, `other-historical-tools.json`, `historical/maps/source-manifest.csv`, research notes and the preserved Git release. The checksum arithmetic is selected from the existing standalone utility; no original application files were edited or replaced. Existing legacy names and historical successes are documented with their fixture-specific limitations in [offline-analysis.md](offline-analysis.md).

The literal term `UPC` was searched with `rg` across the repository, archive notes, manifests, filenames, Python sources, Java importers and XDF definitions. No defining sample or mapping was found; the research notes explicitly preserve the uncertainty. `all UPC` remains unresolved.

## Material limits

The bundle does not contain the original mixed `hpt_read_all_filtered.txt`, raw `flasherfull.log`, raw `flasherpartial.log`, either original full-message log, or `hpt_34_records.csv`. Their recorded raw-frame/message counts and fourteen-case study were read from the manifests. They were not newly reproduced by running those absent files. Raw write-family parsing has synthetic tests; real write-family comparisons use the supplied envelope-hash inventory. The historical protected write-payload transform was not rerun. Record CRC verification, proprietary HPT-container parsing and the undefined UPC family remain unsupported. Exact compatibility outside the supplied ROM/definition pair requires additional evidence. VVEL repeated tail labels and trimming high-bit semantics remain qualified.
