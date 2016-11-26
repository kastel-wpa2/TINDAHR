#! /usr/bin/env python

import sys
from analyzr_core import *


class VerboseDeviceAnalyzer(IPacketAnalyzer):
    _spotted_vendors = {}

    def __init__(self):
        print "Running VerboseDeviceAnalyzer"

    def get_display_filter(self):
        return "wlan.fc.type_subtype == 4"  # Probe requests

    def get_bpf_filter(self):
        return "subtype probereq"

    def analyze_packet(self, packet):
        vendor = packet["WLAN"].sa[0:8]

        if vendor not in self._spotted_vendors:
            self._spotted_vendors[vendor] = {"with_ssid": 0, "broadcast": 0}

        # take care of broadcast probes, not so security critical (still bad
        # for privacy)
        if packet["WLAN_MGT"].ssid == "SSID: ":
            self._spotted_vendors[vendor]["broadcast"] += 1
        else:
            self._spotted_vendors[vendor]["with_ssid"] += 1

    def on_end(self):
        for key, val in self._spotted_vendors.iteritems():
            print key + " (" + AnalyzrCore.lookup_vendor_by_mac(key) + "): " + str(val["with_ssid"]) + " | " + str(val["broadcast"])

verbose_device_analyzer = VerboseDeviceAnalyzer() 
core = AnalyzrCore(verbose_device_analyzer)
core.start()