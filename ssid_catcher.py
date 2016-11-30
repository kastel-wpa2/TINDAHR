#! /usr/bin/env python

import sys
from analyzr_core import *
import re


class SSIDCatcher(IPacketAnalyzer):

    def __init__(self, mac_filter):
        print "Running SSIDCatcher"

        self._mac_filter = mac_filter

    def get_display_filter(self):
        return "wlan.fc.type_subtype == 4"

    def get_bpf_filter(self):
        return "subtype probereq"

    def analyze_packet(self, packet):
        ssid = packet["WLAN_MGT"].ssid

        wlan = packet["WLAN"]

        # Broadcast, we skip this
        if ssid == "SSID: ":
            return

        if self._mac_filter != None and re.match(self._mac_filter, str(wlan.sa)) == None:
            return

        print wlan.sa + " -> " + ssid

    def on_end(self):
        pass


core = AnalyzrCore()

core.get_arg_parser().add_argument("--mac", dest="mac_filter", default=None,
                                      help="Filter by mac address of sender")

ssid_catcher = SSIDCatcher(core.get_parsed_cli_options().mac_filter)
core.register_handler(ssid_catcher)
core.start()
