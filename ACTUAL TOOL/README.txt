G37 / 370Z ECU Tool v13 Combined GUI - User Guide
=================================================

Purpose
-------
This guide explains how to use the final combined G37 / 370Z ECU Tool v13 GUI.

The tool combines three major functions:

1. HPT-style flasher
   - Partial write: 0x008200-0x020000 using 31 81 81 F0 5A + 34 81 records.
   - Full write:    0x008200-0x180000 using 31 81 82 F0 5A + 34 82 records.
   - Dynamic 27 81 / 27 82 seed-key unlock.
   - Checksum patching.
   - 0x44B0 payload encoder.
   - 0x34 record CRC trailer generation.
   - HPT-style finalization and key-cycle prompt.

2. ROM dump GUI
   - Uses read-only 0x23 ReadMemoryByAddress.
   - Dumps in sections.
   - Tries adaptive prep/session modes.
   - Combines sections into combined.bin.

3. Probe / VIN / OS / ECU ID tools
   - 27 seed-only probe.
   - 27 unlock probe.
   - Safe compatibility probe.
   - VIN / OS / ECU ID read attempts using common 22, 1A, and 21 identifiers.

The script file is:

    g37_370z_ecu_tool_v13_combined_gui.py


Safety summary
--------------
This tool has been tested against the ECU server/emulator and the flasher logic is based on the working v12 flasher. Real ECU use still has risk.

Before any real ECU write:

- Use a stable charger or power supply.
- Do not rely on a weak battery.
- Expect the radiator fans to run during programming.
- Keep HPT available as a recovery option.
- Do not unplug the OpenPort or CAN wiring during a write.
- Do not touch the ignition key until the tool prompts you.
- Do not start the vehicle if the tool errors after any 34 records were attempted.
- Always test the exact operation on the ECU server first.

The safest first real ECU write is:

    Partial write
    Current/same tune BIN
    Patch checksums ON
    Stable charger connected


Python and OpenPort setup
-------------------------
For Windows + OpenPort 2.0:

- Use the J2534 raw-CAN backend.
- The common OpenPort DLL is:

    C:\Windows\SysWOW64\op20pt32.dll

- That DLL is usually 32-bit.
- Use 32-bit Python if you get:

    [WinError 193] %1 is not a valid Win32 application

Example Windows launch using 32-bit Python:

    py -3.13-32 g37_370z_ecu_tool_v13_combined_gui.py

For Linux + SocketCAN:

    sudo ip link set can0 down
    sudo ip link set can0 type can bitrate 500000
    sudo ip link set can0 up
    python3 g37_370z_ecu_tool_v13_combined_gui.py


Top connection/project settings
-------------------------------
These settings appear at the top of the GUI and apply to all tabs.

Backend
~~~~~~~
Options:

- j2534_rawcan
  Use this for Windows + OpenPort 2.0.

- socketcan
  Use this for Linux SocketCAN, usually can0.

SocketCAN iface
~~~~~~~~~~~~~~~
Default:

    can0

Only used when Backend is socketcan.

J2534/OpenPort DLL
~~~~~~~~~~~~~~~~~~
Used when Backend is j2534_rawcan.

Typical OpenPort path:

    C:\Windows\SysWOW64\op20pt32.dll

Use Browse DLL to select it.

Baud
~~~~
Default:

    500000

TX ID / RX ID
~~~~~~~~~~~~~
Default G37/370Z diagnostic IDs:

    TX ID: 0x7E0
    RX ID: 0x7E8

Manual 27 key override
~~~~~~~~~~~~~~~~~~~~~~
Normally leave this blank.

Blank means:

    use dynamic seed/key algorithm

Only use manual override if testing a known seed/key pair or diagnosing the security routine.


Flash tab
---------
The Flash tab is for HPT-style partial/full writes from a full 0x180000 BIN.

Base/reference BIN
~~~~~~~~~~~~~~~~~~
This is the known-current or reference ROM file.

Purpose:

- Safety comparison only.
- Helps the tool recommend partial vs full.
- Helps prevent accidentally partial-writing a BIN that differs above the partial range.

The base path is saved in:

    ~/.g37_hpt_flasher_gui_config.json

The tool can auto-load it on startup after it has been set once.

Target full 0x180000 BIN
~~~~~~~~~~~~~~~~~~~~~~~~
This is the BIN you want to flash.

Requirements:

- Must be exactly 0x180000 bytes.
- Must be a full ROM image, not a sparse partial file.
- The tool writes from fixed HPT-style ranges, not from offset 0.

Output folder
~~~~~~~~~~~~~
The tool writes generated/temporary output here, including:

- checksum-patched BIN
- record preview text
- dump folders when using ROM dump
- logs from the GUI session

Mode
~~~~
Options:

Partial
    Uses:

        31 81 81 F0 5A
        34 81 records
        range 0x008200-0x020000
        764 normal records

    Use partial for normal lower calibration edits when the ECU already matches the rest of the BIN.

Full
    Uses:

        31 81 82 F0 5A
        34 82 records
        range 0x008200-0x180000
        12028 normal records

    Use full when the target differs outside the partial range or when you are not sure the ECU matches the target outside the lower calibration area.

Patch BIN checksums before building records
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Recommended: ON.

The tool patches:

    0x8200  lower BE16 checksum
    0x20000 upper BE16 checksum
    0x95F0  XOR32 checksum
    0x95F8  ADD32 checksum

The final implementation patches in the correct dependency order and self-checks the result.

Dry-run/build only
~~~~~~~~~~~~~~~~~~
Recommended for first test.

When ON:

- Builds records.
- Saves preview files.
- Does not send CAN frames.

Enable CAN transmit
~~~~~~~~~~~~~~~~~~~
Must be ON for actual server or ECU flashing.

Safe first workflow:

1. Dry-run/build only ON, Enable CAN transmit OFF.
2. Confirm records build correctly.
3. Dry-run/build only OFF, Enable CAN transmit ON.
4. Test on ECU server.
5. Only after server pass, test real ECU.

Skip 27 unlock (server only)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Normally OFF.

Only use ON if your fake ECU/server is intentionally configured to ignore SecurityAccess.

Do not use this on the real ECU.

Build / Flash
~~~~~~~~~~~~~
Runs the selected operation.

If Dry-run/build only is ON, no CAN frames are sent.
If Enable CAN transmit is ON and dry-run is OFF, the tool will ask for confirmation before transmitting.


Flash sequence used by the tool
-------------------------------
Partial write sequence:

    10 85                         -> 50 85
    3E 01                         -> 7E 01
    10 85                         -> 50 85
    27 81                         -> 67 81 <seed>
    27 82 <computed key>          -> 67 82
    31 81 81 F0 5A                -> 71 81 01
    31 81 01 repeated             -> 71 81 02
    34 81 records                 -> 74 02 each
    31 82 00                      -> 71 82 01 or 71 82 02
    31 82 01 repeated             -> 71 82 02
    34 83 final record            -> 74 02
    Prompt: key OFF at least 3 seconds, key ON, click OK
    10 81                         -> 50 81
    10 85 sanity check            -> 50 85
    10 81                         -> 50 81

Full write is the same except:

    31 81 82 F0 5A
    34 82 records
    range 0x008200-0x180000


Expected successful partial server result
-----------------------------------------
The ECU server summary should look like:

    records_total=765
    records_ok=764
    records_bad=0
    subtype_counts={129: 764}
    seen_final83=True
    programmed_start=0x008200
    programmed_end=0x020000

129 decimal is 0x81.

Expected successful full server result:

    records_total=12029
    records_ok=12028
    records_bad=0
    subtype_counts={130: 12028}
    seen_final83=True
    programmed_start=0x008200
    programmed_end=0x180000

130 decimal is 0x82.


Failure behavior during flashing
--------------------------------
The tool tracks:

- current phase
- records attempted
- records ACKed
- wrong response vs timeout
- negative responses / NRCs

If failure happens before flash records:

- Usually lower risk.
- The tool attempts best-effort cleanup with 10 81.
- You can usually key-cycle and retry.

If failure happens after any 34 record was attempted:

- Treat it as potentially risky.
- Do not start the vehicle.
- Keep stable power connected.
- Recover with HPT or a known-good write/finalization.

If failure happens after records but before finalization/key cycle:

- Do not start the vehicle.
- Do not keep cycling randomly.
- Keep power stable.
- Use HPT or the tool to complete a known-good recovery write.


ROM Dump tab
------------
The ROM Dump tab is a GUI version of the adaptive section dumper.

It uses read-only 0x23 ReadMemoryByAddress. It does not arm flash and does not send write records.

Dump start
~~~~~~~~~~
Default:

    0x000000

For a full ROM dump, use 0x000000.

Total bytes
~~~~~~~~~~~
Default:

    0x180000

For a full G37/370Z ROM dump, use 0x180000.

Section size
~~~~~~~~~~~~
Default is typically:

    0x10000

The tool dumps one section at a time and writes section files.

Chunk
~~~~~
Default is typically:

    0x3F

This is the read size attempted for each 0x23 request.

If a vehicle/OS does not like larger chunks, the adaptive dumper will try smaller sizes.

Output folder
~~~~~~~~~~~~~
The dump creates a timestamped dump folder inside the selected output folder.

Expected files:

- manifest.json
- section_000000_010000.bin
- section_010000_020000.bin
- etc.
- combined.bin

Prep modes
~~~~~~~~~~
Comma-separated list of prep modes the dumper tries.

Common default set:

    none,unlock85,c0_83_fb,c0_83_81_fb,fb_only,c0_only,unlock85_fb,c0_83_fb_unlock_no_restore,c0_83_unlock85

Meaning:

none
    Try reading without prep.

unlock85
    Enter 10 85, tester present, 27 unlock.

c0_83_fb
    Try 10 C0, 21 83, 10 FB style prep.

c0_83_81_fb
    Try 10 C0, 21 83, 21 81, 10 FB style prep.

fb_only
    Try 10 FB only.

c0_only
    Try 10 C0 only.

unlock85_fb
    Unlock in 10 85, then try 10 FB.

c0_83_fb_unlock_no_restore
    Try C0/83/FB path, then unlock 85 without restoring session.

c0_83_unlock85
    Try C0/83 path, then unlock 85.

Read formats
~~~~~~~~~~~~
Comma-separated list of 0x23 request formats.

Default:

    a4_s2,a3_s2,a3_s1

Meaning:

- a4_s2: 4-byte address, 2-byte size
- a3_s2: 3-byte address, 2-byte size
- a3_s1: 3-byte address, 1-byte size

Start ROM Dump
~~~~~~~~~~~~~~
Starts the dump.

Recommended first dump test:

    start:        0x000000
    total:        0x1000
    section size: 0x1000
    chunk:        0x20 or 0x3F

After a small test passes, do a full dump:

    start:        0x000000
    total:        0x180000
    section size: 0x10000
    chunk:        0x3F

Cancel Dump
~~~~~~~~~~~
Requests cancellation.

The current request may finish first; then the dump stops and keeps the section files already written.

Important dump notes
~~~~~~~~~~~~~~~~~~~~
- The combined v13 dump tab currently creates a new timestamped dump each time.
- It writes a manifest, but full resume behavior is not as mature as the older command-line dumper.
- For important full dumps, keep the old CLI dumper available as a fallback.
- Always compare dump size and hash when possible.


Probe / VIN / OS tab
--------------------
This tab is for checking whether another G37/370Z ECU or OS variant appears compatible before attempting any flash.

Probe 27 seed only
~~~~~~~~~~~~~~~~~~
Sends:

    10 85
    3E 01
    27 81

It logs:

    seed
    computed key

It does not send the key.
It does not arm flash.
It is the safest SecurityAccess test.

Probe 27 unlock
~~~~~~~~~~~~~~~
Sends:

    10 85
    3E 01
    27 81
    27 82 <computed key>

Expected pass:

    67 82

This confirms the dynamic seed/key algorithm works on that ECU/OS variant.

It does not arm flash.

Safe compatibility probe
~~~~~~~~~~~~~~~~~~~~~~~~
This avoids write/erase/finalize services.

It checks common sessions and SecurityAccess behavior:

    10 81
    10 85
    10 C0
    10 FB
    27 81 / 27 82 if supported

Then it runs the info read attempts.

It intentionally does not send:

    31 81 F0 5A
    34
    36
    37
    reset
    erase
    write

Unlock before VIN/OS read
~~~~~~~~~~~~~~~~~~~~~~~~~
When checked, the info reader performs 27 unlock before trying ID reads.

Use it if VIN/OS reads are denied without security access.

Read VIN / OS / ECU IDs
~~~~~~~~~~~~~~~~~~~~~~~
The tool tries several read-only ID requests.

UDS 22 DID candidates include:

    F190 - VIN
    F191 - ECU HW number
    F193 - supplier ECU HW number
    F195 - supplier ECU SW number
    F188 - vehicle manufacturer ECU SW number
    F189 - vehicle manufacturer ECU SW version
    F18C - ECU serial number
    F198 - programming date / repair shop style info
    F19D - installation date style info

KWP/Nissan 1A candidates include:

    1A 80
    1A 81
    1A 82
    1A 83
    1A 87
    1A 88
    1A 90
    1A 91
    1A 92
    1A 94
    1A 9A

Nissan local ID 21 candidates include:

    21 80
    21 81
    21 82
    21 83
    21 90
    21 91
    21 92
    21 9A

Negative responses are normal. Different OS variants may answer different IDs.


Recommended compatibility workflow for a different G37/370Z ECU
---------------------------------------------------------------
1. Connect to the ECU with stable power.
2. Open Probe / VIN / OS tab.
3. Run Probe 27 seed only.
4. If it returns a seed and calculated key, run Probe 27 unlock.
5. Run Read VIN / OS / ECU IDs without unlock.
6. If many IDs are denied, check Unlock before VIN/OS read and retry.
7. Save/copy the output log.
8. Do not flash until:
   - 27 unlock passes,
   - VIN/OS/read info looks plausible,
   - you have a known-good full BIN for that ECU/OS,
   - and server tests pass with that BIN.


Recommended server test workflow
--------------------------------
Use this before every real ECU test.

1. Start the ECU server on Linux.
2. Open v13 GUI on Windows or Linux.
3. Select backend:
   - Windows/OpenPort: j2534_rawcan
   - Linux/can0: socketcan
4. Set TX/RX:

       TX 0x7E0
       RX 0x7E8

5. Select Base/reference BIN.
6. Select Target BIN.
7. Select Output folder.
8. Choose Partial mode first.
9. Turn on Patch BIN checksums.
10. Turn on Dry-run/build only.
11. Click Build / Flash.
12. Confirm it builds 764 partial records.
13. Turn off Dry-run/build only.
14. Turn on Enable CAN transmit.
15. Click Build / Flash again.
16. After the server run, compare server output:

       emu_flash_full.bin

   against the intended patched target BIN.


Recommended first real ECU workflow
-----------------------------------
1. Put charger/power supply on the car.
2. Use the current/same tune BIN as Target.
3. Use the current/same tune BIN as Base/reference.
4. Use Partial mode.
5. Patch checksums ON.
6. Dry-run first.
7. Confirm:

       Mode: partial
       Range: 0x008200-0x020000
       Records: 764
       Recommended mode: partial

8. Enable CAN transmit.
9. Start flash.
10. Do not touch key/cables until prompted.
11. At prompt, key OFF for at least 3 seconds.
12. Wait until relays/fans/modules settle if possible.
13. Key ON.
14. Click OK.
15. Wait for post-cycle communication check.
16. Only start vehicle if the tool says complete and there are no failure warnings.


When to use partial vs full
---------------------------
Use Partial when:

- Changes are normal lower calibration edits.
- Base/reference analysis says differences are within 0x008200-0x01FFFF.
- You know the ECU already matches the unwritten upper region.

Use Full when:

- Differences exist at or above 0x020000.
- You are not sure what is currently on the ECU.
- You are restoring a full known-good image.

Do not use either mode if:

- The file is not exactly 0x180000 bytes.
- It is a sparse decoded file instead of a full ROM.
- The BIN is from a different ECU/OS and compatibility has not been checked.
- Voltage is unstable.


Troubleshooting
---------------
WinError 193 loading OpenPort DLL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Cause:

- 64-bit Python trying to load 32-bit op20pt32.dll.

Fix:

- Install/use 32-bit Python.
- Run with py -3.x-32.

Timeout waiting for 10 85 response
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Check:

- CAN wiring.
- OpenPort connected to same bus as ECU/server.
- TX/RX IDs correct.
- Baud 500000.
- Linux can0 up if using server.
- Server running if using server.

Use candump on Linux:

    candump can0

Expected first request:

    7E0  [8]  02 10 85 00 00 00 00 00

27 unlock fails
~~~~~~~~~~~~~~~
Check:

- Manual key override is blank.
- Dynamic algorithm is being used.
- ECU is in 10 85 session.
- Try Probe 27 seed only first.
- Try Probe 27 unlock next.

Wrong response during first 34 record
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If the response is:

    30 xx xx

that is ISO-TP FlowControl, not a UDS flash ACK.

v12/v13 should ignore stale FlowControl while waiting for the actual:

    74 02

Failure after records attempted
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Treat as serious.

Do not start the vehicle.
Keep power stable.
Recover with HPT or a known-good write.

VIN/OS reads all negative
~~~~~~~~~~~~~~~~~~~~~~~~~
This can be normal.

Try:

- Unlock before VIN/OS read.
- Safe compatibility probe.
- Different session path.
- Compare with known logs from similar ECU/OS.

ROM dump stops mid-section
~~~~~~~~~~~~~~~~~~~~~~~~~~
Use smaller chunk size.
Try different prep modes.
Keep the old CLI dumper available for resume-heavy work.


Important addresses and constants
---------------------------------
ROM size:

    0x180000

Writable/HPT flash start:

    0x008200

Partial range:

    0x008200-0x020000

Full range:

    0x008200-0x180000

Block size:

    0x80

Partial record count:

    764

Full record count:

    12028

CAN IDs:

    TX 0x7E0
    RX 0x7E8

0x44B0 transform key:

    0x6E6C2EE9

Record CRC target:

    0xF0B8

Checksum fields:

    0x8200  lower 16-bit sum
    0x20000 upper 16-bit sum
    0x95F0  XOR32
    0x95F8  ADD32

Known rev limiter scalar:

    offset: 0x92B2
    RPM = raw_u16 * 25 / 32

Example:

    7500 RPM -> raw 0x2580
    5000 RPM -> raw 0x1900


Final notes
-----------
The v13 combined tool is meant to make the workflow easier, but the safest practice remains:

1. Probe first.
2. Dump/read when possible.
3. Test on server.
4. Partial-write same/current tune first.
5. Only then write a small controlled change.
6. Save logs from every session.

For actual tuning use, keep the normal mode simple:

- full 0x180000 BINs only
- base/reference BIN set
- patch checksums ON
- partial or full fixed HPT-style ranges only
- no arbitrary write ranges unless in a future developer-only mode
