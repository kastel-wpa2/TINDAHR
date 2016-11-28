#! /usr/bin/env python

import sys
from analyzr_core import *


class VerboseDeviceAnalyzer(IPacketAnalyzer):
    _spotted_manufacturers = {}

    def __init__(self):
        print "Running VerboseDeviceAnalyzer"

    def get_display_filter(self):
        return "wlan.fc.type_subtype == 4"  # Probe requests

    def get_bpf_filter(self):
        return "subtype probereq"

    def analyze_packet(self, packet):
        vendor = packet["WLAN"].sa[0:8]

        if vendor not in self._spotted_manufacturers:
            self._spotted_manufacturers[vendor] = {"with_ssid": 0, "broadcast": 0}

        # take care of broadcast probes, not so security critical (still bad
        # for privacy)
        if packet["WLAN_MGT"].ssid == "SSID: ":
            self._spotted_manufacturers[vendor]["broadcast"] += 1
        else:
            self._spotted_manufacturers[vendor]["with_ssid"] += 1

    def on_end(self):
        grouped_by_manufacturer = {}
        for key, val in self._spotted_manufacturers.iteritems():
            looked_up_maufacturer = AnalyzrCore.lookup_vendor_by_mac(key)
            if looked_up_manufacturer not in grouped_by_manufacturer:
                grouped_by_manufacturer[looked_up_manufacturer] = {
                    "count_with_ssid": val["with_ssid"],
                    "count_broadcast": val["broadcast"],
                    "mac_prefixes": [key]
                }
            else:
                grouped_by_manufacturer[looked_up_manufacturer]["count_with_ssid"] += val["with_ssid"]
                grouped_by_manufacturer[looked_up_manufacturer]["count_broadcast"] += val["broadcast"]                
                grouped_by_manufacturer[looked_up_manufacturer]["mac_prefixes"].append(key)

        for (name, manufacturer) in grouped_by_manufacturer.iteritems():
            print name + ": " + str(manufacturer["count_with_ssid"]) + " | " + str(manufacturer["count_broadcast"]) + " (" + ", ".join(manufacturer["mac_prefixes"]) + ")"
            
verbose_device_analyzer = VerboseDeviceAnalyzer() 
core = AnalyzrCore(verbose_device_analyzer)
core.start()