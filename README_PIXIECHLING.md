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
4. **Optional Step 2**: Scans clients connected to the selected BSSIDs and lets you select allowed clients per BSSID (`none`, `all`, `keep` existing, or comma-separated numbers). Each client can be given a name.
5. Saves the whitelist to `pixiechling_whitelist.json` (BSSID + SSID + channel + allowed_clients)

> If `allowed_clients` is defined for a BSSID (non-empty), any client not in the list will trigger an **unauthorized client** alert and deauth in modes 2 and 3. If empty, client filtering is disabled for that BSSID.

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
- **Unauthorized client detection**: if `allowed_clients` is set for a whitelisted BSSID, unknown clients are automatically deauthenticated
- Client summary every 15 seconds (includes unauthorized client report)

**Mode-specific options:**
- `-5`: Include 5 GHz channels (38 channels instead of 13)

> ⚠️ **Whitelist required**: Run mode 1 first to define which BSSIDs to exclude.

---

### Mode 3 — Rogue AP Detection + Counter-Offensive

Continuous monitoring to detect rogue access points, signal relays, deauth attacks, and **spoofed deauth floods**.
**As soon as SSID spoofing, BSSID cloning (evil twin), or a deauth attack on a protected BSSID/client is detected**, an automatic counter-offensive is launched.

```bash
sudo python3 pixiechling.py -m 3
```

**6 detection types + counter-offensive:**

| Detection | Description | Alert Color | Action |
|-----------|-------------|-------------|--------|
| **SSID Spoofing** | An unknown BSSID broadcasts the same SSID as a whitelisted AP | 🟥 Red | **Deauth + CTS-to-self** |
| **BSSID Cloning / Evil Twin** | A whitelisted BSSID is seen on a different channel than the one recorded in the whitelist | 🟥 Red | **Deauth + CTS-to-self** |
| **Deauth Attack** | Deauth frames targeting a protected BSSID or its clients from an unknown MAC | 🟥 Red | **Deauth attacker + CTS-to-self NAV defense** |
| **Spoofed Deauth Attack** | Deauth frames where the source MAC is spoofed as a protected BSSID or allowed client. Detected via 3-signal analysis: Sequence Number anomaly, RSSI anomaly, deauth flood rate | 🟥 Red | **CTS-to-self NAV defense** |
| **Unauthorized Client** | A client connects to a whitelisted BSSID but is not in its `allowed_clients` list | 🟥 Red | **Deauth** |
| **Signal Relay / Repeater** | A BSSID acts as a client of another BSSID (ToDS/WDS frames between APs) | 🟪 Magenta | Alert |

**Spoofed deauth detection — 3-signal analysis:**

The most advanced deauth attack spoofs both the source BSSID and client MAC, making MAC-based identification impossible. Pixiechling uses 3 independent signals to detect these attacks:

| Signal | How it works | Threshold |
|--------|-------------|-----------|
| **Sequence Number (SC)** | Each station maintains a monotonic frame counter. Spoofed deauth frames have inconsistent SC relative to the real AP's beacon sequence. | Gap > 50 |
| **RSSI** | The attacker's radio is at a different physical location — signal strength differs from the real AP baseline (tracked from beacons). | Delta > 15 dBm |
| **Deauth flood rate** | A normal disconnection sends 1–2 deauth frames. A flood of deauth frames from a protected BSSID in a short window is anomalous. | ≥ 5 frames in 10s |

If **any** of the 3 signals confirms the deauth is spoofed, CTS-to-self NAV defense is engaged on the target BSSID.

> ⚠️ No deauth counter-attack is sent for spoofed deauths (the source MAC is our own BSSID or client — attacking it would harm our own network). CTS-to-self is the only safe counter-measure: it reserves the wireless medium for 30ms, causing stations to defer transmission and ignore the attacker's deauth frames.

**Counter-offensive threads:**

| Thread | Function |
|--------|----------|
| **Capture** | Channel hopping + rogue/deauth detection + client tracking |
| **Deauth** | Deauth on rogue AP clients + unauthorized clients + deauth attackers |
| **Latency** | CTS-to-self flooding on rogue BSSIDs + protected BSSIDs under deauth attack (NAV=30ms) |

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

  [!!!] UNAUTHORIZED CLIENT DETECTED
        BSSID       : 11:22:33:44:55:66 (MyNetwork)
        Client MAC  : ff:ee:dd:cc:bb:aa
        Channel     : 6
        Time        : Fri Mar 21 14:32:00 2026
        [>>>] DEAUTH ENGAGED

  [!!!] DEAUTH ATTACK ON PROTECTED BSSID
        Target BSSID : 11:22:33:44:55:66 (MyNetwork)
        Attacker MAC : cc:cc:cc:cc:cc:cc
        Victim client: dd:ee:ff:44:55:66
        Channel      : 6
        Time         : Fri Mar 21 14:33:00 2026
        [>>>] DEAUTH DEFENSE ENGAGED

  [!!!] SPOOFED DEAUTH ATTACK DETECTED
        Target BSSID : 11:22:33:44:55:66 (MyNetwork)
        Spoofed src  : 11:22:33:44:55:66
        Channel      : 6
        Time         : Fri Mar 21 14:34:00 2026
        Evidence     : SC anomaly (gap=347), RSSI anomaly (delta=22 dBm), Flood (8 in 10s)
        [>>>] CTS-TO-SELF DEFENSE ENGAGED
```

**Periodic summary (every 15s):**
- Counters: number of SSID spoofs, BSSID clones, relays detected
- **Deauth defense**: number of attackers countered, BSSIDs protected with CTS-to-self, victim clients
- **Spoofed deauth**: number of spoofed floods detected, BSSIDs under CTS-to-self protection
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
| `pixiechling_whitelist.json` | BSSID whitelist `{bssid: {ssid, channel, allowed_clients}}` | mode 1 |
| `pixiechling_relays.json` | Detected relay map `{relay: {ssid, upstream}}` | mode 3 |

### pixiechling_whitelist.json format

```json
{
  "11:22:33:44:55:66": {
    "ssid": "MyNetwork",
    "channel": 6,
    "allowed_clients": {
      "aa:bb:cc:11:22:33": "Phone",
      "dd:ee:ff:44:55:66": "Laptop"
    }
  },
  "aa:bb:cc:dd:ee:ff": {
    "ssid": "OtherNetwork",
    "channel": 11,
    "allowed_clients": {}
  }
}
```

- `allowed_clients`: `{client_mac: name}` — authorized client MACs for this BSSID. If empty `{}`, client filtering is disabled for that BSSID.

> Backward compatible: older formats (`{bssid: ssid}`, `[bssid, ...]`, or without `allowed_clients`) are automatically converted on load.

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
│   ├── scan_clients()         → client discovery on selected BSSIDs
│   └── mode_scan_whitelist()  → interactive BSSID + client selection UI
│
├── Mode 2 : Capture / Replay
│   ├── Thread 1 : capture_loop()    → channel hop + client tracking + buffer + unauthorized client detection
│   ├── Thread 2 : deauth_loop()     → bidirectional deauth (reason=7) + unauthorized client deauth
│   ├── Thread 3 : latency_loop()    → CTS-to-self flooding (NAV=30ms)
│   └── Main     : replay + summary  → per-channel replay, SC tracking, unauth client report
│
└── Mode 3 : Rogue AP Detection + Counter-Offensive
    ├── Thread 1 : capture_loop()   → channel hop + detection + rogue client tracking
    │   ├── _handle_pkt()
    │   │   ├── Check 1 : SSID spoofing → triggers counter-offensive
    │   │   ├── Check 2 : BSSID cloning / evil twin → triggers counter-offensive
    │   │   ├── Check 3 : Deauth attack on protected BSSID/client → deauth defense
    │   │   ├── Check 4 : Unauthorized client on whitelisted BSSID → deauth
    │   │   ├── Check 5 : Signal relay / repeater (ToDS/WDS)
    │   │   └── Client tracking on rogue BSSIDs
    ├── Thread 2 : deauth_loop()    → deauth rogue clients + unauthorized + deauth attackers
    ├── Thread 3 : latency_loop()   → CTS-to-self on rogue BSSIDs + protected BSSIDs under attack
    └── Main     : summary loop     → status + deauth defense + counter-offensive + unauthorized clients + relay map
```

---

## Disclaimer

⚠️ **This tool is intended for educational purposes and authorized security testing only.**

Using this tool on networks without explicit authorization is illegal. The deauthentication, latency injection, and packet replay features can disrupt WiFi communications. Only use this tool on networks you own or for which you have written penetration testing authorization.

---

## License

This project is distributed under the GPLv3 license. See the [LICENSE](LICENSE) file for details.
