#! /usr/bin/env python

import sys
from analyzr_core import *


class VerboseDeviceAnalyzer(IPacketAnalyzer):
    _spotted_manufacturers = {}

    def __init__(self, dedup):
        print "Running VerboseDeviceAnalyzer"
        self._dedup = dedup
        self._already_known_devices_with_ssid = set()
        self._already_known_devices_broadcasting = set()        

    def get_display_filter(self):
        return "wlan.fc.type_subtype == 4"  # Probe requests

    def get_bpf_filter(self):
        return "subtype probereq"

    def analyze_packet(self, packet, channel):
        sa = packet["WLAN"].sa
        vendor = sa[0:8]

        if vendor not in self._spotted_manufacturers:
            self._spotted_manufacturers[vendor] = {
                "with_ssid": 0, "broadcast": 0}

        # take care of broadcast probes, not so security critical (still bad
        # for privacy)
        if packet["WLAN_MGT"].ssid == "SSID: ":
            if sa in self._already_known_devices_broadcasting and self._dedup:
                return
            self._spotted_manufacturers[vendor]["broadcast"] += 1
            self._already_known_devices_broadcasting.add(sa)
        else:
            if sa in self._already_known_devices_with_ssid and self._dedup:
                return
            self._spotted_manufacturers[vendor]["with_ssid"] += 1
            self._already_known_devices_with_ssid.add(sa)

    def on_end(self):
        grouped_by_manufacturer = {}
        for key, val in self._spotted_manufacturers.iteritems():
            looked_up_manufacturer = AnalyzrCore.lookup_vendor_by_mac(key)
            if looked_up_manufacturer not in grouped_by_manufacturer:
                grouped_by_manufacturer[looked_up_manufacturer] = {
                    "count_with_ssid": val["with_ssid"],
                    "count_broadcast": val["broadcast"],
                    "mac_prefixes": [key]
                }
            else:
                grouped_by_manufacturer[looked_up_manufacturer][
                    "count_with_ssid"] += val["with_ssid"]
                grouped_by_manufacturer[looked_up_manufacturer][
                    "count_broadcast"] += val["broadcast"]
                grouped_by_manufacturer[looked_up_manufacturer][
                    "mac_prefixes"].append(key)

        for (name, manufacturer) in grouped_by_manufacturer.iteritems():
            print name + ": " + str(manufacturer["count_with_ssid"]) + " | " + str(manufacturer["count_broadcast"]) + " (" + ", ".join(manufacturer["mac_prefixes"]) + ")"

        print "Total number of devices sending probes containing SSID: " + str(len(self._already_known_devices_with_ssid)) + ", devices broadcasting: " + str(len(self._already_known_devices_broadcasting))

core = AnalyzrCore()

core.get_arg_parser().add_argument("-d, --dedup", dest="dedup", default=True,
                                      help="Multiple requests of one device are only counted once.")

tool = VerboseDeviceAnalyzer(core.get_parsed_cli_options().dedup)
core.register_handler(tool)
core.start()
