#! /usr/bin/env python

import sys
from analyzr_core import *


class SSIDCatcher(IPacketAnalyzer):

    def __init__(self):
        print "Running SSIDCatcher"

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

        print wlan.sa + " -> " + wlan.da + " (" + ssid + ")"

    def on_end(self):
        pass

ssid_catcher = SSIDCatcher()
core = AnalyzrCore(ssid_catcher)
core.start()
