# Pixiechling

```
██████╗ ██╗██╗  ██╗██╗███████╗ ██████╗██╗  ██╗██╗     ██╗███╗   ██╗ ██████╗
██╔══██╗██║╚██╗██╔╝██║██╔════╝██╔════╝██║  ██║██║     ██║████╗  ██║██╔════╝
██████╔╝██║ ╚███╔╝ ██║█████╗  ██║     ███████║██║     ██║██╔██╗ ██║██║  ███╗
██╔═══╝ ██║ ██╔██╗ ██║██╔══╝  ██║     ██╔══██║██║     ██║██║╚██╗██║██║   ██║
██║     ██║██╔╝ ██╗██║███████╗╚██████╗██║  ██║███████╗██║██║ ╚████║╚██████╔╝
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝
```

**WiFi Traffic Capture, Replay & Rogue AP Detection Tool**

Pixiechling is a multi-mode WiFi security tool that can scan, capture, replay 802.11 traffic, detect rogue access points, and identify signal relays/repeaters.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage Modes](#usage-modes)
  - [Mode 1 — Scan & Whitelist](#mode-1--scan--whitelist)
  - [Mode 2 — Capture / Replay / Deauth / Latency Injection](#mode-2--capture--replay--deauth--latency-injection)
  - [Mode 3 — Rogue AP Detection + Counter-Offensive](#mode-3--rogue-ap-detection--counter-offensive)
- [CLI Options](#cli-options)
- [Generated Files](#generated-files)
- [Examples](#examples)
- [Disclaimer](#disclaimer)

---

## Prerequisites

- **OS**: Linux (with 802.11 monitor mode support)
- **Python**: 3.6+
- **WiFi Interfaces**: 2 monitor-mode capable interfaces (one for capture, one for replay/injection)
- **Privileges**: root (required for monitor mode and packet injection)

### Python Dependencies

```bash
pip3 install scapy termcolor
```

### System Tools

- `iwconfig` (`wireless-tools` package)
- `ip` (`iproute2` package)

---

## Installation

```bash
git clone https://github.com/<repo>/WiFi-Pineapple-Detector.git
cd WiFi-Pineapple-Detector
pip3 install scapy termcolor
```

---

## Configuration

### pixiechling.conf

WiFi interface configuration file:

```ini
[interfaces]
capture = wlan0mon
replay = wlan1mon
```

| Parameter | Description |
|-----------|-------------|
| `capture` | Monitor mode interface for packet capture |
| `replay`  | Monitor mode interface for replay and injection |

> The script automatically offers to enable monitor mode if the interface is not already in it.

---

## Usage Modes

### Mode 1 — Scan & Whitelist

Scans WiFi channels to discover BSSIDs (access points) and lets you select which ones to add to the whitelist.

```bash
sudo python3 pixiechling.py -m 1
```

**How it works:**
1. Scans channels 1-13 (2.4 GHz) or 1-13 + 36-165 (with `-5`)
2. Displays a numbered table of discovered BSSIDs with their SSIDs **and detected channel**
3. User selects BSSIDs to whitelist (comma-separated numbers, or `all`)
4. Saves the whitelist to `pixiechling_whitelist.json` (BSSID + SSID + channel)

**Mode-specific options:**
- `-t <seconds>`: Scan duration (default: 30s)
- `-5`: Include 5 GHz channels

---

### Mode 2 — Capture / Replay / Deauth / Latency Injection

Full offensive mode running 4 simultaneous threads on **non-whitelisted** BSSIDs:

```bash
sudo python3 pixiechling.py -m 2
```

**4 parallel threads:**

| Thread | Function |
|--------|----------|
| **Capture** | Channel hopping + packet capture + real-time client tracking |
| **Deauth** | Continuous bidirectional deauthentication frames (AP → client + client → AP, reason=7) |
| **Latency** | Spoofed CTS-to-self frame injection (duration=30000µs) to force stations into NAV wait |
| **Replay** | Replays captured packets on the correct channel, with coherent SC (Sequence Control) and preserved timing |

**Features:**
- 15-second sliding buffer
- Per-channel packet grouping before replay
- Per-MAC Sequence Control (SC) tracking for flow continuity
- Original inter-packet timing preservation
- Client summary every 15 seconds

**Mode-specific options:**
- `-5`: Include 5 GHz channels (38 channels instead of 13)

> ⚠️ **Whitelist required**: Run mode 1 first to define which BSSIDs to exclude.

---

### Mode 3 — Rogue AP Detection + Counter-Offensive

Continuous monitoring to detect rogue access points and signal relays.
**As soon as SSID spoofing or BSSID cloning (evil twin) is detected**, an automatic counter-offensive is launched (deauth + CTS-to-self latency injection) against the rogue AP and its clients.

```bash
sudo python3 pixiechling.py -m 3
```

**3 detection types + counter-offensive:**

| Detection | Description | Alert Color | Action |
|-----------|-------------|-------------|--------|
| **SSID Spoofing** | An unknown BSSID broadcasts the same SSID as a whitelisted AP | 🟥 Red | **Deauth + CTS-to-self** |
| **BSSID Cloning / Evil Twin** | A whitelisted BSSID is seen on a different channel than the one recorded in the whitelist | 🟥 Red | **Deauth + CTS-to-self** |
| **Signal Relay / Repeater** | A BSSID acts as a client of another BSSID (ToDS/WDS frames between APs) | 🟪 Magenta | Alert |

**Counter-offensive threads (activated upon SSID spoofing or evil twin detection):**

| Thread | Function |
|--------|----------|
| **Capture** | Channel hopping + rogue AP detection + tracking clients connected to the rogue |
| **Deauth** | Bidirectional deauthentication of rogue AP clients (reason=7) |
| **Latency** | CTS-to-self flooding on the rogue AP BSSID (NAV=30ms) |

**Alert examples:**

```
  [!!!] SSID SPOOFING DETECTED
        Rogue BSSID : aa:bb:cc:dd:ee:ff
        Spoofed SSID: MyNetwork
        Legit BSSID : 11:22:33:44:55:66
        Channel     : 6
        Time        : Fri Mar 21 14:30:00 2026
        [>>>] COUNTER-OFFENSIVE ENGAGED

  [!!!] BSSID CLONE / EVIL TWIN DETECTED
        BSSID       : 11:22:33:44:55:66
        SSID        : MyNetwork
        Expected ch : 6
        Seen on ch  : 11
        Time        : Fri Mar 21 14:30:30 2026
        [>>>] COUNTER-OFFENSIVE ENGAGED

  [!!!] SIGNAL RELAY / REPEATER DETECTED
        Relay BSSID   : aa:bb:cc:dd:ee:ff (MyNetwork_EXT)
        Upstream BSSID: 11:22:33:44:55:66 (MyNetwork)
        Channel       : 6
        Time          : Fri Mar 21 14:31:00 2026
```

**Periodic summary (every 15s):**
- Counters: number of SSID spoofs, BSSID clones, relays detected
- **Counter-offensive**: number of rogue APs under attack, number of clients being deauthenticated
- Relay network map: `relay (SSID) → upstream (SSID)`

**Output file:** Detected relays are saved to `pixiechling_relays.json`

> ⚠️ **Whitelist required**: Run mode 1 first.
> ⚠️ **2 interfaces required**: capture + replay (for counter-offensive).

---

## CLI Options

```
usage: Pixiechling [-h] -m {1,2,3} [-c CONFIG] [-t SCAN_TIME] [-5]
```

| Option | Long | Description | Default | Modes |
|--------|------|-------------|---------|-------|
| `-m` | `--mode` | Execution mode (1, 2 or 3) | *required* | all |
| `-c` | `--config` | Path to configuration file | `pixiechling.conf` | all |
| `-t` | `--scan-time` | Scan duration in seconds | `30` | 1 |
| `-5` | `--5ghz` | Include 5 GHz channels (36-165) | `false` | 1, 2, 3 |

### Covered Channels

| Band | Channels | Count |
|------|----------|-------|
| 2.4 GHz | 1–13 | 13 |
| 5 GHz | 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165 | 25 |
| **2.4 + 5 GHz** | — | **38** |

---

## Generated Files

| File | Description | Created by |
|------|-------------|------------|
| `pixiechling.conf` | Interface configuration (create manually) | user |
| `pixiechling_whitelist.json` | BSSID whitelist `{bssid: {ssid, channel}}` | mode 1 |
| `pixiechling_relays.json` | Detected relay map `{relay: {ssid, upstream}}` | mode 3 |

### pixiechling_whitelist.json format

```json
{
  "11:22:33:44:55:66": {
    "ssid": "MyNetwork",
    "channel": 6
  },
  "aa:bb:cc:dd:ee:ff": {
    "ssid": "OtherNetwork",
    "channel": 11
  }
}
```

> Backward compatible: older formats (`{bssid: ssid}` or `[bssid, ...]`) are automatically converted on load.

### pixiechling_relays.json format

```json
{
  "aa:bb:cc:dd:ee:ff": {
    "ssid": "MyNetwork_EXT",
    "upstream": {
      "11:22:33:44:55:66": "MyNetwork"
    }
  }
}
```

---

## Examples

```bash
# Quick 2.4 GHz scan (15 seconds)
sudo python3 pixiechling.py -m 1 -t 15

# Full 2.4 + 5 GHz scan (60 seconds)
sudo python3 pixiechling.py -m 1 -t 60 -5

# Capture/replay + deauth + latency injection (2.4 GHz)
sudo python3 pixiechling.py -m 2

# Capture/replay on all bands
sudo python3 pixiechling.py -m 2 -5

# Rogue AP detection + relays (2.4 GHz)
sudo python3 pixiechling.py -m 3

# Rogue AP detection + relays (2.4 + 5 GHz)
sudo python3 pixiechling.py -m 3 -5

# With a custom config file
sudo python3 pixiechling.py -m 2 -c /etc/pixiechling/custom.conf -5
```

---

## Architecture

```
pixiechling.py
├── Mode 1 : Scan & Whitelist
│   ├── scan_bssids()          → channel hop + beacon capture
│   └── mode_scan_whitelist()  → interactive BSSID selection UI
│
├── Mode 2 : Capture / Replay
│   ├── Thread 1 : capture_loop()    → channel hop + client tracking + buffer
│   ├── Thread 2 : deauth_loop()     → bidirectional deauth (reason=7)
│   ├── Thread 3 : latency_loop()    → CTS-to-self flooding (NAV=30ms)
│   └── Main     : replay + summary  → per-channel replay, SC tracking
│
└── Mode 3 : Rogue AP Detection + Counter-Offensive
    ├── Thread 1 : capture_loop()   → channel hop + detection + rogue client tracking
    │   ├── _handle_pkt()
    │   │   ├── Check 1 : SSID spoofing → triggers counter-offensive
    │   │   ├── Check 2 : BSSID cloning / evil twin → triggers counter-offensive
    │   │   ├── Check 3 : Signal relay / repeater (ToDS/WDS)
    │   │   └── Client tracking on rogue BSSIDs
    ├── Thread 2 : deauth_loop()    → bidirectional deauth on rogue clients
    ├── Thread 3 : latency_loop()   → CTS-to-self on rogue BSSIDs (NAV=30ms)
    └── Main     : summary loop     → status + counter-offensive stats + relay map
```

---

## Disclaimer

⚠️ **This tool is intended for educational purposes and authorized security testing only.**

Using this tool on networks without explicit authorization is illegal. The deauthentication, latency injection, and packet replay features can disrupt WiFi communications. Only use this tool on networks you own or for which you have written penetration testing authorization.

---

## License

This project is distributed under the GPLv3 license. See the [LICENSE](LICENSE) file for details.
