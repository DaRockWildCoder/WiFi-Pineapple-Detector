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
from collections import deque

from termcolor import colored
from argparse import RawTextHelpFormatter
from scapy.all import sniff
from scapy.sendrecv import sendp
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

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

DESCRIPTION = """
Pixiechling - WiFi Traffic Capture & Replay Tool

Modes:

  1 : Scan BSSIDs and select whitelist
  2 : Start capture/replay loop (requires whitelist)
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


def load_whitelist():
    if not os.path.isfile(WHITELIST_FILE):
        return []
    with open(WHITELIST_FILE, "r") as f:
        return json.load(f)


def save_whitelist(whitelist):
    with open(WHITELIST_FILE, "w") as f:
        json.dump(whitelist, f, indent=2)


# ──────────────────────────────────────────────
#  Mode 1 : Scan & whitelist selection
# ──────────────────────────────────────────────

def scan_bssids(capture_iface):
    """Scan channels 1-13 and collect unique BSSIDs with their SSIDs."""
    discovered = {}

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
                discovered[bssid] = ssid

    print(colored("[*] Scanning BSSIDs on all channels (this takes ~30 s) ...", "cyan"))
    for ch in range(1, 14):
        subprocess.run(["iwconfig", capture_iface, "channel", str(ch)], check=False)
        sniff(iface=capture_iface, count=10, timeout=2, prn=_handle_beacon)

    return discovered


def mode_scan_whitelist(capture_iface):
    """Interactive mode: display BSSIDs, let user pick whitelist entries."""
    discovered = scan_bssids(capture_iface)

    if not discovered:
        print(colored("[!] No BSSIDs found. Make sure the interface is in monitor mode.", "red"))
        return

    # Display table
    bssid_list = sorted(discovered.items(), key=lambda x: x[1])
    print("\n" + colored(" #   BSSID               SSID", "yellow"))
    print(colored(" " + "-" * 50, "yellow"))
    for idx, (bssid, ssid) in enumerate(bssid_list, start=1):
        print(" {:<4} {}   {}".format(idx, bssid, ssid))

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

    save_whitelist(chosen)
    print(colored("[+] Whitelist saved ({} BSSIDs):".format(len(chosen)), "green"))
    for b in chosen:
        print("    " + b)


# ──────────────────────────────────────────────
#  Mode 2 : Capture / Replay loop
# ──────────────────────────────────────────────

class ReplayBuffer:
    """Thread-safe rolling buffer that keeps packets from the last `window` seconds."""

    def __init__(self, window=15):
        self.window = window
        self.lock = threading.Lock()
        self.packets = deque()

    def add(self, pkt):
        now = time.time()
        with self.lock:
            self.packets.append((now, pkt))
            self._prune(now)

    def get_packets(self):
        now = time.time()
        with self.lock:
            self._prune(now)
            return [pkt for _, pkt in self.packets]

    def _prune(self, now):
        while self.packets and (now - self.packets[0][0]) > self.window:
            self.packets.popleft()


def mode_replay(capture_iface, replay_iface):
    """Capture traffic on iface0 between whitelisted BSSIDs and their clients,
    then replay the last 15 s of frames on iface1 toward the BSSID."""

    whitelist = load_whitelist()
    if not whitelist:
        print(colored("[!] No whitelist found. Run mode 1 first.", "red"))
        sys.exit(1)

    whitelist_set = set(b.lower() for b in whitelist)
    buf = ReplayBuffer(window=15)
    stop_event = threading.Event()

    def _on_sigint(sig, frame):
        print(colored("\n[*] Stopping ...", "yellow"))
        stop_event.set()

    signal.signal(signal.SIGINT, _on_sigint)

    print(colored("[+] Whitelist loaded ({} BSSIDs):".format(len(whitelist)), "green"))
    for b in whitelist:
        print("    " + b)
    print(colored("[*] Capture iface : " + capture_iface, "cyan"))
    print(colored("[*] Replay  iface : " + replay_iface, "cyan"))
    print(colored("[*] Starting capture/replay loop (Ctrl+C to stop) ...", "cyan"))

    # ── Capture thread ──
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
            # Keep packet only if NO address matches a whitelisted BSSID
            if not (whitelist_set & set(addrs)):
                buf.add(pkt)

        while not stop_event.is_set():
            for ch in range(1, 14):
                if stop_event.is_set():
                    return
                subprocess.run(
                    ["iwconfig", capture_iface, "channel", str(ch)],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                sniff(iface=capture_iface, timeout=1, prn=_handle_pkt)

    cap_thread = threading.Thread(target=capture_loop, daemon=True)
    cap_thread.start()

    # ── Replay loop (main thread) ──
    while not stop_event.is_set():
        time.sleep(15)
        packets = buf.get_packets()
        if not packets:
            print(colored("[*] Buffer empty, waiting ...", "yellow"))
            continue

        print(colored("[>] Replaying {} packets on {} ...".format(len(packets), replay_iface), "green"))
        for pkt in packets:
            if stop_event.is_set():
                break
            try:
                sendp(pkt, iface=replay_iface, verbose=False)
            except Exception as e:
                print(colored("[!] Replay error: " + str(e), "red"))
                break

    cap_thread.join(timeout=5)
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
        choices=["1", "2"],
        help="1 = Scan & whitelist  |  2 = Capture/replay loop",
    )
    parser.add_argument(
        "-c", "--config",
        default=CONFIG_FILE,
        help="Path to config file (default: pixiechling.conf)",
    )
    args = parser.parse_args()

    capture_iface, replay_iface = load_config(args.config)

    print(banner_intro)
    print(colored("[*] Config loaded", "cyan"))
    print(colored("[*] Capture interface (0) : " + capture_iface, "cyan"))
    print(colored("[*] Replay  interface (1) : " + replay_iface, "cyan"))
    print()

    if args.mode == "1":
        mode_scan_whitelist(capture_iface)
    elif args.mode == "2":
        mode_replay(capture_iface, replay_iface)
