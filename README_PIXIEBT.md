# PixieBT

```
██████╗ ██╗██╗  ██╗██╗███████╗██████╗ ████████╗
██╔══██╗██║╚██╗██╔╝██║██╔════╝██╔══██╗╚══██╔══╝
██████╔╝██║ ╚███╔╝ ██║█████╗  ██████╔╝   ██║
██╔═══╝ ██║ ██╔██╗ ██║██╔══╝  ██╔══██╗   ██║
██║     ██║██╔╝ ██╗██║███████╗██████╔╝   ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═════╝    ╚═╝
```

**Bluetooth Device Monitoring & Protection Tool**

PixieBT monitors the Bluetooth environment around your devices, detects unauthorized connections **to** your protected devices, and automatically launches counter-offensives against intruders.

Key concept: a **two-level whitelist** defines which devices are yours, and which peers are allowed to connect to each one.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage Modes](#usage-modes)
  - [Mode 1 — Scan & Whitelist](#mode-1--scan--whitelist)
  - [Mode 2 — Monitor & Counter-Offensive](#mode-2--monitor--counter-offensive)
  - [Mode 3 — Capture & Replay](#mode-3--capture--replay)
  - [Mode 4 — Audio MITM (Whisper Injection)](#mode-4--audio-mitm-whisper-injection)
- [CLI Options](#cli-options)
- [Generated Files](#generated-files)
- [Examples](#examples)
- [Architecture](#architecture)
- [Disclaimer](#disclaimer)

---

## Prerequisites

- **OS**: Linux (with BlueZ stack)
- **Python**: 3.6+
- **Bluetooth adapter**: HCI-compatible (built-in or USB dongle)
- **Privileges**: root (required for HCI commands and L2CAP operations)

### Python Dependencies

```bash
pip3 install termcolor
```

### System Tools

| Tool | Package | Used for |
|------|---------|----------|
| `hciconfig` | `bluez` | Interface management |
| `hcitool` | `bluez` | Scanning (inquiry, lescan, connections) |
| `l2ping` | `bluez` | L2CAP flood counter-offensive |
| `bluetoothctl` | `bluez` | BLE device discovery (fallback) |
| `btmon` | `bluez` | HCI traffic capture & replay (mode 3) |
| `hcidump` | `bluez` | HCI traffic capture (fallback for btmon) |
| `hcireplay` | `bluez` | HCI replay (optional, preferred for mode 3) |

**Mode 4 additionally requires:**
- A **second Bluetooth adapter** (e.g. `hci1`) — *only for MITM relay mode*
- `.wav` whisper files in a directory **OR** a text file + `espeak-ng` / `espeak` for automatic generation
- **A2DP playback** (TV/speakers): `pulseaudio` or `pipewire-pulse` + one of `paplay`, `pw-play`, `aplay`

```bash
# Debian/Ubuntu
sudo apt install bluez espeak-ng pulseaudio-utils

# Arch
sudo pacman -S bluez bluez-utils
```

---

## Installation

```bash
git clone https://github.com/<repo>/WiFi-Pineapple-Detector.git
cd WiFi-Pineapple-Detector
pip3 install termcolor
```

---

## Configuration

### pixiebt.conf

Bluetooth interface configuration file:

```ini
[bluetooth]
interface = hci0
```

| Parameter | Description |
|-----------|-------------|
| `interface` | HCI Bluetooth interface (e.g., `hci0`, `hci1`) |

> The script automatically offers to bring the interface UP if it is down.

---

## Usage Modes

### Mode 1 — Scan & Whitelist

Two-step interactive setup: first select **your devices** (to protect), then for each one, define which **peers are allowed** to connect to it.

```bash
sudo python3 pixiebt.py -m 1
```

**Step 1 — Select your devices:**
1. Scans Classic BT + BLE (configurable)
2. Displays a numbered table of all discovered devices
3. You select which ones are **yours** (the ones to protect)

**Step 2 — Define allowed peers per device:**
4. For each protected device, you select which **other devices** are permitted to connect to it
5. Options: comma-separated numbers, `all`, `none` (any connection = alert), or `keep` (keep existing peers)
6. Saves everything to `pixiebt_whitelist.json`

**Interactive flow example:**
```
  =============================================
    STEP 1 — Select YOUR devices (to PROTECT)
  =============================================
   #   MAC                 NAME                         TYPE
   ---------------------------------------------------------------
   1   AA:BB:CC:DD:EE:01   MyHeadphones                 classic
   2   AA:BB:CC:DD:EE:02   FitnessBand                  ble
   3   11:22:33:44:55:66   MyPhone                      classic
   4   77:88:99:AA:BB:CC   UnknownDevice                ble

  [?] Enter numbers of YOUR devices to protect: 1,2

  =============================================
    STEP 2 — For each device, select ALLOWED peers
  =============================================

  ┌─ Device: AA:BB:CC:DD:EE:01 (MyHeadphones)
  │  Available peers:
  │   1    11:22:33:44:55:66   MyPhone [classic]
  │   2    77:88:99:AA:BB:CC   UnknownDevice [ble]
  │
  │  [?] Allowed peers for this device: 1
  └─ Saved: MyHeadphones — 1 peer(s)

  ┌─ Device: AA:BB:CC:DD:EE:02 (FitnessBand)
  │  [?] Allowed peers for this device: none
  └─ Saved: FitnessBand — no peers (monitor-only)

  WHITELIST SUMMARY
  -----------------------------------------------------------
  AA:BB:CC:DD:EE:01 (MyHeadphones) [classic]
    └─ allowed: 11:22:33:44:55:66 (MyPhone)
  AA:BB:CC:DD:EE:02 (FitnessBand) [ble]
    └─ no peers allowed (any connection = alert)
```

**Mode-specific options:**
- `-t <seconds>`: Scan duration per scan type (default: 10s)
- `--no-ble`: Disable BLE scanning (Classic BT only)

---

### Mode 2 — Monitor & Counter-Offensive

Continuous monitoring with 4 parallel threads. Detects any device that is **not an allowed peer** of your protected devices and launches automatic counter-offensives.

```bash
sudo python3 pixiebt.py -m 2
```

**Detection logic:**
- A device that is in "my devices" = protected, never attacked
- A device that is a designated "allowed peer" of at least one protected device = trusted
- Any other device = intruder → **alert + counter-offensive**
- If a device has `"allowed_peers": {}` (none), ANY connection involving it triggers an alert

**4 parallel threads:**

| Thread | Function | Interval |
|--------|----------|----------|
| **Classic scan** | Inquiry scan for non-whitelisted Classic BT devices | 30s |
| **BLE scan** | Advertisement scan for non-whitelisted BLE devices | 15s |
| **Connection monitor** | Checks active HCI connections for unauthorized MACs | 5s |
| **Counter-offensive** | Automatic retaliation against each detected intruder | 5s |

**Counter-offensive by device type:**

| Device Type | Counter-Measure | Effect |
|-------------|----------------|--------|
| **Classic BT** | `l2ping -s 600 -f` (L2CAP flood) + name request spam | Saturates the intruder's BT radio, makes it unreachable |
| **BLE** | Connection flood (`lecc` → `ledc` repeated) | Saturates the BLE radio, prevents legitimate connections |
| **Active connection** | L2CAP flood (same as Classic) | Disrupts and degrades the unauthorized connection |

**Alert example:**

```
  [!!!] UNAUTHORIZED CONNECTION → MYHEADPHONES
        Intruder MAC : 77:88:99:AA:BB:CC
        Name         : UnknownDevice
        Type         : ble
        Target device: AA:BB:CC:DD:EE:01 (MyHeadphones)
        Via          : active connection
        Time         : Sat Mar 22 14:30:00 2026
        [>>>] COUNTER-OFFENSIVE ENGAGED

  [>>>] L2CAP flood started → 77:88:99:AA:BB:CC
```

**Periodic summary (every 15s):**
- Number of intruders detected
- Number of active L2CAP floods
- Scan counters (classic, BLE, connection checks)
- Per-intruder status: MAC, name, type, detection count, flood status

```
[*] Status: 2 intruder(s) detected | 1 active flood(s) | scans: 4 classic, 8 BLE, 45 conn checks
[*] Counter-offensive: 2 L2CAP flood(s) started, 5 BLE disruption(s)
    AA:BB:CC:DD:EE:FF (SuspiciousDevice) [classic] — seen 3x via inquiry scan [FLOODING]
    11:22:33:44:55:66 (<unknown>) [ble] — seen 7x via BLE scan
```

> ⚠️ **Whitelist required**: Run mode 1 first to define your trusted devices.

---

### Mode 3 — Capture & Replay

Scans for non-whitelisted Bluetooth devices, captures 1 second of HCI traffic, then replays the capture a configurable number of times (default: 10x).

```bash
sudo python3 pixiebt.py -m 3
sudo python3 pixiebt.py -m 3 -r 20    # replay 20x instead of 10
```

**How it works:**

1. **Discovery** — Scans for Classic BT + BLE devices not in the whitelist
2. **Capture** — For each target, records 1 second of HCI traffic using `btmon` (or `hcidump`)
3. **Replay** — Replays the captured traffic N times using `hcireplay` / `btmon -r` / `hcidump -r`
4. **Loop** — Repeats every 15 seconds with a fresh scan

**Capture & Replay tools (priority order):**

| Step | Tool | Fallback |
|------|------|----------|
| Capture | `btmon -w` | `hcidump -w` |
| Replay | `hcireplay` | `btmon -r` → `hcidump -r` |

**Alert example:**

```
[─] Scan cycle 1 ...
    [*] 2 non-whitelisted device(s) found:
        77:88:99:AA:BB:CC (UnknownSpeaker) [classic]
        DD:EE:FF:00:11:22 (<unknown>) [ble]

  [▶] TARGET: 77:88:99:AA:BB:CC (UnknownSpeaker)
    [*] Capturing 1 s of traffic ...
    [+] Captured 1842 bytes → /tmp/pixiebt_captures/cap_778899AABBCC_1711108200.bin
    [*] Replaying 10x ...
    [+] Replayed 10/10 times

  [▶] TARGET: DD:EE:FF:00:11:22 (<unknown>)
    [*] Capturing 1 s of traffic ...
    [!] No traffic captured, skipping.

[*] Cycle 1 complete — 1 capture(s), 10 replay(s), 1 target(s)
```

**Captures** are saved in `/tmp/pixiebt_captures/`.

> ⚠️ **Whitelist required**: Run mode 1 first.
> ⚠️ **btmon or hcidump required**: Install `bluez` package.

---

### Mode 4 — Audio MITM (Whisper Injection)

Injects whispered voices into Bluetooth audio. Supports **SCO** (voice profile) and **A2DP** (media profile) devices.

**Three sub-modes** (selected interactively after scanning):

| Sub-mode | Profile | Adapters | Selection | Description |
|----------|---------|----------|-----------|-------------|
| **Direct injection (SCO)** | HFP/HSP | 1 | 1 target | Connect via SCO and inject whispers on multi-source detection |
| **Direct playback (A2DP)** | A2DP | 1 | 1 target | Connect to TV/speaker/headphones and play whispers via PulseAudio/PipeWire |
| **MITM relay** | HFP/HSP | 2 | 2 targets | Intercept audio between device A ↔ B and inject whispers in both directions |

> With a single adapter, only direct injection is available. With `-o`, the user can choose either.
> A2DP mode is **automatic** — if SCO fails (TV, speakers, headphones in media mode), the tool falls back to A2DP playback.

**Detection heuristic** (3-signal analysis):
1. **Energy floor** — RMS energy > 500 (audio is not silence)
2. **Zero-crossing rate** — ZCR in [0.05, 0.40] (not pure tone / not pure noise)
3. **Energy variance** — Coefficient of variation > 15% across 4 sub-windows (dynamic multi-source scene)

**Steps:**
1. **Generate** *(optional)* — If `-f` is provided (or default `whispers.txt` used), generates WAV files using `espeak-ng`/`espeak` with the `+whisper` voice variant
2. **Load** — Reads `.wav` files, resamples to 8 kHz 16-bit mono (SCO CVSD)
3. **Discover** — Scans for all available Bluetooth devices (classic + BLE)
4. **Select** — Interactive selection: **1 target** (direct) or **2 targets** (MITM)
5. **Disconnect** — Force-disconnects target(s)
6. **Pair** — `bluetoothctl trust` + `pair`
7. **Connect** — Tries SCO socket first; if SCO fails, falls back to A2DP via `bluetoothctl connect` + PulseAudio/PipeWire sink detection
8. **Inject / Relay / Playback** — SCO: listen + inject. MITM: relay A→B / B→A. A2DP: play WAVs via `paplay`/`pw-play`/`aplay`
9. **Detect** — SCO modes: whisper PCM mixed on `_detect_multi_source()` trigger. A2DP: whispers played sequentially with random pauses

**Alert examples:**

*Single target (SCO — voice devices):*
```
[*] Target: AA:BB:CC:DD:EE:01 (SomeHeadphones)
[*] Trying SCO connection (voice profile) ...
    [+] SCO → AA:BB:CC:DD:EE:01 (SomeHeadphones)
[*] Mode  : SCO direct injection

[+] Direct injection active — whispers sent on multi-source detection
[*] Packets: 2410 | Injections: 18
```

*Single target (A2DP fallback — TV, speakers, headphones):*
```
[*] Target: AA:BB:CC:DD:EE:02 (LivingRoom-TV)
[*] Trying SCO connection (voice profile) ...
[*] SCO not available — switching to A2DP sink mode (TV/speaker/headphones)
[*] Connecting via A2DP ...
    [+] A2DP → AA:BB:CC:DD:EE:02 (LivingRoom-TV)
[*] Mode  : A2DP playback (whispers played on device)

[+] A2DP injection active — whispers played directly on target
[*] Whispers played: 12
```

*Dual target (MITM relay):*
```
  [1 target]  Direct injection (whisper sent to device)
  [2 targets] MITM relay (intercept audio between A ↔ B)

[?] Select target(s) — comma-separated (e.g. 1 or 1,2): 1,2

[*] Target A: AA:BB:CC:DD:EE:01 (SomeHeadphones)
[*] Target B: AA:BB:CC:DD:EE:02 (SmartSpeaker)
[*] Mode    : MITM relay

[+] MITM relay active — whispers injected on multi-source detection
[*] Relay: 4820 pkt(s) | Injections: 37 | A→B: 2400/18 | B→A: 2420/19
```

> ⚠️ **1 adapter minimum** (direct injection / A2DP playback). 2nd adapter optional for MITM relay (`-o`).
> ⚠️ **Whisper source** : `.wav` files (`-w`) **or** text file (`-f`) **or** default `whispers.txt`.
> ⚠️ **A2DP devices** (TV, speakers, headphones): SCO is attempted first; if it fails, the tool automatically falls back to A2DP playback via PulseAudio/PipeWire.

---

## CLI Options

```
usage: PixieBT [-h] -m {1,2,3,4} [-c CONFIG] [-t SCAN_TIME] [-r REPLAY_COUNT]
               [--no-ble] [-o HCI] [-w DIR] [-f FILE]
               [--whisper-volume VOL] [-l LANG]
```

| Option | Long | Description | Default | Modes |
|--------|------|-------------|---------|-------|
| `-m` | `--mode` | Execution mode (1, 2, 3 or 4) | *required* | all |
| `-c` | `--config` | Path to configuration file | `pixiebt.conf` | all |
| `-t` | `--scan-time` | Scan duration in seconds | `10` | 1 |
| `-r` | `--replay-count` | Number of times to replay captured traffic | `10` | 3 |
| | `--no-ble` | Disable BLE scanning (Classic BT only) | `false` | all |
| `-o` | | Second BT adapter for MITM relay (optional) | — | 4 |
| `-w` | `--whispers-dir` | Directory containing `.wav` whisper files | — | 4 |
| `-f` | `--f` | Text file (word/phrase per line) for auto TTS generation via espeak | — | 4 |
| | `--whisper-volume` | Whisper injection volume (0.0–1.0) | `0.15` | 4 |
| `-l` | `--whisper-lang` | Espeak language code for TTS (`en`, `fr`, `de`, `es`, `it`, `ru`, ...) | `en` | 4 |

---

## Generated Files

| File | Description | Created by |
|------|-------------|------------|
| `pixiebt.conf` | Interface configuration (create manually) | user |
| `pixiebt_whitelist.json` | Two-level whitelist `{device: {name, type, allowed_peers}}` | mode 1 |

### pixiebt_whitelist.json format

```json
{
  "AA:BB:CC:DD:EE:01": {
    "name": "MyHeadphones",
    "type": "classic",
    "allowed_peers": {
      "11:22:33:44:55:66": "MyPhone"
    }
  },
  "AA:BB:CC:DD:EE:02": {
    "name": "FitnessBand",
    "type": "ble",
    "allowed_peers": {}
  }
}
```

| Field | Description |
|-------|-------------|
| `name` | Human-readable name of your device |
| `type` | `classic` or `ble` |
| `allowed_peers` | Map of `{MAC: name}` for devices allowed to connect to this device. Empty `{}` means **any connection triggers an alert**. |

> Backward compatible: older formats (`{mac: name}`, `{mac: {name, type}}` without peers, or `[mac, ...]`) are automatically converted on load.

---

## Examples

```bash
# Quick scan (10 seconds, classic + BLE)
sudo python3 pixiebt.py -m 1

# Longer scan (30 seconds)
sudo python3 pixiebt.py -m 1 -t 30

# Classic Bluetooth only scan (no BLE)
sudo python3 pixiebt.py -m 1 --no-ble

# Start monitoring & protection
sudo python3 pixiebt.py -m 2

# Monitor without BLE
sudo python3 pixiebt.py -m 2 --no-ble

# Capture & replay (10x, default)
sudo python3 pixiebt.py -m 3

# Capture & replay 20x
sudo python3 pixiebt.py -m 3 -r 20

# Capture & replay, classic BT only
sudo python3 pixiebt.py -m 3 --no-ble

# With a custom config file
sudo python3 pixiebt.py -m 2 -c /etc/pixiebt/custom.conf

# Audio MITM with whisper injection (2 adapters required)
sudo python3 pixiebt.py -m 4 -o hci1 -w /home/user/whispers/

# Single-target direct injection (1 adapter, uses default whispers.txt)
sudo python3 pixiebt.py -m 4

# Audio MITM with louder whispers (25% volume)
sudo python3 pixiebt.py -m 4 -o hci1 -w ./whispers/ --whisper-volume 0.25

# Audio MITM, classic BT only
sudo python3 pixiebt.py -m 4 -o hci1 -w ./whispers/ --no-ble

# Audio MITM — generate WAVs from a text file (no pre-existing .wav needed)
sudo python3 pixiebt.py -m 4 -o hci1 -f words.txt

# Generate WAVs from text + save to specific dir + custom volume
sudo python3 pixiebt.py -m 4 -o hci1 -f words.txt -w ./my_whispers/ --whisper-volume 0.20

# French whispers (fichier français inclus)
sudo python3 pixiebt.py -m 4 -l fr -f whispers_fr.txt

# French with 2 adapters for MITM relay
sudo python3 pixiebt.py -m 4 -o hci1 -l fr -f whispers_fr.txt
```

---

## Architecture

```
pixiebt.py
├── Mode 1 : Scan & Whitelist
│   ├── scan_classic()          → HCI inquiry scan
│   ├── scan_ble()              → BLE advertisement scan + bluetoothctl fallback
│   ├── scan_all()              → combined scan
│   └── mode_scan_whitelist()   → interactive device selection UI
│
├── Mode 2 : Monitor & Counter-Offensive
│   ├── Thread 1 : classic_scan_loop()   → periodic Classic BT inquiry (30s)
│   ├── Thread 2 : ble_scan_loop()       → periodic BLE scan (15s)
│   ├── Thread 3 : connection_monitor()  → active connection check (5s)
│   ├── Thread 4 : counter_loop()        → counter-offensive dispatch
│   │   ├── Classic/Active : l2ping flood + name request spam
│   │   └── BLE            : lecc/ledc connection flood
│   └── Main     : summary loop (15s) → status + intruder list + flood stats
│
├── Mode 3 : Capture & Replay
│   ├── _discover_targets()    → scan for non-whitelisted devices
│   ├── _capture_traffic()     → btmon/hcidump capture (1s window)
│   ├── _replay_traffic()      → hcireplay/btmon/hcidump replay (Nx)
│   └── Main loop              → discover → capture → replay (15s cycle)
│
└── Mode 4 : Audio MITM — Whisper Injection
    ├── _generate_whispers_from_text() → espeak TTS: text file → .wav (optional)
    ├── _load_whispers()       → load .wav → resample to 8kHz 16-bit mono
    ├── _detect_multi_source() → energy + ZCR + CV heuristic (3-signal)
    ├── _mix_pcm()             → mix whisper into SCO audio with clamping
    ├── _pair_device()         → bluetoothctl trust + pair
    ├── _sco_connect()         → AF_BLUETOOTH / BTPROTO_SCO socket
    ├── _inject_thread()       → single-target: listen + inject on same socket
    ├── _relay_thread() (×2)   → MITM: A→B and B→A with injection on detection
    └── Main flow              → [generate] → discover → select 1 or 2 → inject/relay
```

---

## Disclaimer

⚠️ **This tool is intended for educational purposes and authorized security testing only.**

Using this tool on Bluetooth devices without explicit authorization is illegal. The L2CAP flood, BLE connection flood, capture & replay, and audio MITM features can disrupt Bluetooth communications. Intercepting audio between devices may violate wiretapping and privacy laws. Only use this tool on devices you own or for which you have written penetration testing authorization.

---

## License

This project is distributed under the GPLv3 license. See the [LICENSE](LICENSE) file for details.
