# G37 offline capture analysis

This is an additive, saved-file workspace. All files that existed at cleanup commit `99229fea9e6e6f81d528ebef2906203de321dd04` retain their paths and bytes. The historical v13 app and standalone checksum app remain available. The new launcher is `ACTUAL TOOL/g37_offline_capture_gui.py`; the shared engine is `g37offline/`.

Requires Python 3.10+ and, for the desktop window only, Tk. There are no third-party Python dependencies. The CLI, tests and checksum integration do not import Tk or the combined application's transport, authentication or programming implementation. Raw inputs are opened for reading.

## Desktop

From the repository root:

```shell
python "ACTUAL TOOL/g37_offline_capture_gui.py"
```

1. Browse to the saved capture. For the supplied response-only export, also select `read-segments.csv` as the address sidecar.
2. Select an optional XDF, comparison BIN or full base. The bundled XDF is selected initially. For a raw BIN, explicitly select `full` or `interval`; an interval also needs its ROM offset, such as `0x8200`.
3. Analyze. Review captured coverage separately from the selected base view, all four checksum results, differences and maps. Select an object and a cell to see original titles, raw bytes, engineering value, formula, source digest and source lines. Duplicate titles retain their IDs. Uncovered cells display `unavailable`; unresolved addresses display `unresolved`.
4. Choose `segments`, `observed` or `overlay`, then export into a new run directory. Existing directories are refused. Input changes invalidate the preview. Source changes since analysis also prevent export. Cancel stops the worker without publishing a final directory.

The Events and diagnostics tab preserves counts and line references. Access events omit identifiers and sensitive payloads and contribute zero ROM bytes. It is an offline event view, not an authentication implementation.

## Headless

Unpack the archive outside the checkout. The following examples assume the archive directory is `../G37_Historical_Archive`. Choose a fresh output directory for every run.

```shell
python -m g37offline ../G37_Historical_Archive/historical/fixtures/read-data-responses.log --sidecar ../G37_Historical_Archive/historical/fixtures/read-segments.csv --xdf "ACTUAL TOOL/DEF/TESTED.xdf" --compare "ACTUAL TOOL/DEF/Original.bin" --mode observed --output ../g37-results/read
```

This reconstructs data from CAN response frames. The sidecar supplies addresses, lengths and inclusive response-frame line spans; its `data_hex` is compared afterwards and never supplies output bytes. Addresses cannot be independently inferred from response-only frames. The report records that external association. Independently reconstruct the normalized segments:

```shell
python -m g37offline ../G37_Historical_Archive/historical/fixtures/read-segments.csv --mode observed --output ../g37-results/segments-check
```

Inspect a known full image or an explicitly addressed interval:

```shell
python -m g37offline "ACTUAL TOOL/DEF/Original.bin" --binary full --xdf "ACTUAL TOOL/DEF/TESTED.xdf"
python -m g37offline ../G37_Historical_Archive/historical/fixtures/teat_decoded_sparse_0x008200_0x180000.bin --binary interval --offset 0x8200 --mode segments --output ../g37-results/interval
```

A declared BIN establishes the supplied file's bytes and selected ROM offset, not its capture history. To bind and verify the archived decoded artifact to an inventory run, use the provided manifest example. Its paths assume the layout above. Copy it outside the checkout and adjust paths if needed, retaining the evidence hashes and offset:

```shell
python -m g37offline ../G37_Historical_Archive/historical/fixtures/write-record-envelope-index.csv --decoded-manifest examples/decoded-interval-manifest.json --mode segments --output ../g37-results/verified-interval
```

The manifest binds the inventory hash, run, claimed range, decoded bytes and reference slice. Its `capture_evidence_file` and `capture_evidence_sha256` must identify evidence connecting the inventory/run to the same capture digest and address range. Producer name/version are recorded. The artifact comparison is independently rerun; the historical capture evidence and original transform are not independently reproduced. Altering an input binding, selected variant, capture association, range or artifact digest rejects import. The evidence is a bound historical declaration, not proof that the raw capture was supplied.

To create an overlay, explicitly add `--base path/to/compatible-full.bin --mode overlay`. The report identifies every base-supplied span. Selecting a base asserts the user's intended pairing; equal size alone does not verify compatibility. A base overlay never qualifies as a fully observed reconstruction of the capture.

`--request-id` and `--response-id` configure recorded read request/response identifiers; defaults are `0x7E0` and `0x7E8`. The historical seven-byte address/length request and explicit address-and-length-format requests are supported. Read associations are scoped by channel and session; ambiguous outstanding requests are rejected. Optional `# session NAME` markers separate runs. Direction is retained when `RX` or `TX` occurs before the identifier.

The CLI exits 0 for completed supported analysis/export, 2 for invalid input/export or a refused observed-image request, and 130 for keyboard cancellation. A partial supported analysis can exit 0: inspect coverage and diagnostics. Checksum failures are reported individually rather than redefining analysis success.

## Exports and coverage

All ranges are half-open ROM byte ranges. File byte zero of a segment corresponds to the start offset in its filename and manifest. Internal unobserved bytes are never exported as calibration.

| Mode | Output and requirements |
| --- | --- |
| `observed` | `observed.bin`, exactly 0x180000 bytes, all covered by input observations or verified decoded segments, no conflicts, no base/fill bytes. File imports remain labeled as file imports. |
| `segments` | One `segment-START-END.bin` for each contiguous recovered interval. Zero segments for opaque inventory alone. |
| `overlay` | `base-overlay.bin`, full selected base plus recovered intervals, conflict free, with base spans in the report. |

Every run includes `report.json`, `maps.json`, `summary.txt` and `SHA256SUMS.txt`. Exports are staged, flushed and finalized as a new directory under an exclusive run lock. Cancellation and failed staging remove temporary output. Inputs are rehashed before export. No overwrite option is provided.

The report separates missing, observed, verified decoded, base, deliberately filled and conflicting byte states, with provenance per source span. It counts identical overlaps and preserves both sources of disagreements. Existing observations are never silently replaced. A repeated FF value is ordinary observed data only if its source establishes that byte. Requested-range coverage allows a tail-only fixture to report exactly six missing bytes without implying the preceding ROM was captured.

Comparisons retain contiguous byte-difference runs, unmatched tails and coverage exclusions. Map-aware differences retain changes even when masking/scaling leaves the displayed value unchanged. All objects sharing a changed range remain represented. The checker reuses an AST-selected subset of the existing standalone file's reader/calculator; it does not import the GUI or patch the image. Available checksum fields are calculated independently of reconstruction. Base/fill participation is labeled.

## Formats and limits

| Input family | Status | Interpretation |
| --- | --- | --- |
| Timestamped compact candump, classic CAN | Supported | Strict length/hex validation; ISO-TP SF/FF/CF/FC with sequence wrap and padding exclusion. |
| Spaced `<channel> <id> [DLC] <bytes>` | Supported | Optional timestamp and direction; same reassembly engine. |
| Response-only read export + CSV/JSON sidecar | Supported | Frames supply bytes; sidecar supplies external address provenance; disagreement excludes a block. |
| Mixed historical or explicit-ALFID read requests/responses | Supported | Same-channel/session pairing with length, negative-reply and outstanding-request diagnostics. |
| Already-reassembled `<channel> <id> PDU <hex>` | Supported normalized format | No ISO-TP pass. Undocumented historical message-log dialects need conversion or a sample. |
| Normalized addressed segment CSV | Supported | Header `rom_offset_hex,length,data_hex`; original association metadata retained. |
| Supplied envelope-hash inventory | Supported inventory | Counts, claimed extents and envelope differences; zero decoded ROM bytes from hashes. |
| Raw write-family envelopes | Partial | Ordinary 136-byte subtype-0x81 records claim 128-byte extents. Known terminal digest claims zero. Unknown records remain diagnostic/opaque. No protected-body decoding or CRC validation is claimed. |
| Decoded interval/full raw BIN | Explicit declaration required | Interval offset required; full size must be exact. Capture provenance is separate. |
| Verified decoded-artifact manifest | Supported | Checks file/run/range/digest/reference association; records producer and qualification. |
| XDF XML | Supported subset | Header defaults/base, signed/unsigned integers, endian, 32/64-bit float, row/column-major byte-aligned strides, flags/masks, labels/embedded axes/referenced objects, restricted arithmetic. Unsupported storage, external math variables and formulas remain visible errors. |
| CAN FD, extended/mixed ISO-TP addressing or extended-length ISO-TP | Unsupported | No inference from the classic-CAN fixtures. |
| Proprietary `.hpt` containers | Unresolved | No container decoder; extension does not identify firmware. |
| `all UPC` | Unresolved | No confirmed sample/definition. UDS, XDF and Ghidra symbols retain their separate meanings. |

Input files are bounded to 256 MiB; XDF XML to 10 MiB and one million cells per plane. DTD/entity declarations are refused. Equations use a bounded arithmetic AST walker, with explicit `X`/`x` handling, bit masks and visible divide-by-zero/unsupported-operation errors. Arbitrary Python execution is not used for formulas. Known VVEL axis labels repeat near their tails; their physical meaning remains unverified. Trimming bit 7 semantics remain unresolved.

Calibration identity states distinguish an exact known stock hash, a derivative bound by a supplied lineage manifest, a manually selected unverified definition/profile, and a partial/unsupported calibration identity. A derivative manifest has `rom_sha256`, `base_sha256`, and `xdf_sha256`; this verifies the supplied binding, not the truth of otherwise unsupported historical lineage. A modified image is expected to differ from the stock whole-image hash.

## Migration and historical preservation

The old `rebuilt_uds23_0x00000000.bin` is six bytes short. Rebuild from the response frames and address sidecar; do not append FF and call those bytes captured. Historical padding/overlays are file artifacts whose synthetic/base contributions must be separately documented. The archived `teat...bin` begins at ROM 0x8200, not zero. `test2.bin` is the exact historical comparison fixture and passes only one checksum field; its old stock label does not override its bytes.

Legacy source and archive contents are not replaced. `can_rom_filter_rebuilder_gui.py` is evidence for the short-read defect; `g37_hpt_isotp_gui.py` supports spaced-log inventory but skipped compact read lines. `g37_flash_diff_gui.py` established contiguous BIN diffs and unequal tails. The checksum calculator's four-field golden evidence is reused. The thirteen XDF builders, Java label importers, historical padding utility and recorded decoder variants keep their original purposes. Detailed source hashes and verification scope are in the external archive's manifests.

## Validation

```shell
python -m unittest discover -s tests -v
```

For the real archive regressions, set `G37_EVIDENCE` to its extracted root, then run the same command. For example on Linux:

```shell
G37_EVIDENCE=/absolute/path/G37_Historical_Archive python -m unittest discover -s tests -v
```

The public synthetic fixtures contain invented bytes, including a varied six-byte final response. The optional evidence tests verify all archive hashes, full reconstruction, independent normalized reconstruction, tail provenance, both candump syntaxes, truncated/varied tails, envelope inventory counts, artifact association failures, exact historical map coverage and all checksum fields. Tk integration runs when `DISPLAY` is available; it exercises the normal analysis/export callbacks and compares the GUI report and BIN to the headless engine on the same evidence. The original mixed read/write logs and the fourteen-case legacy CSV are absent from this bundle; their manifest counts are historical evidence, not newly parsed results.

See [offline-validation.md](offline-validation.md) for the measured results and limitations of this implementation run.
