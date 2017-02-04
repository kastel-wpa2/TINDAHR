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

    def get_bpf_filter(self):
        return "subtype probereq"

    def analyze_packet(self, packet, channel):
        sa = packet.addr2
        vendor = AnalyzrCore.lookup_vendor_by_mac(sa)

        if vendor not in self._spotted_manufacturers:
            self._spotted_manufacturers[vendor] = {
                "with_ssid": 0, "broadcast": 0}

        # take care of broadcast probes, not so security critical (still bad
        # for privacy)
        if packet.addr2 == "ff:ff:ff:ff:ff:ff":
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
        for name, manufacturer in self._spotted_manufacturers.iteritems():
            print name + ": " + str(manufacturer["with_ssid"]) + " | " + str(manufacturer["broadcast"])

        print "Total number of devices sending probes containing SSID: " + str(len(self._already_known_devices_with_ssid)) + ", devices broadcasting: " + str(len(self._already_known_devices_broadcasting))

core = AnalyzrCore()

core.get_arg_parser().add_argument("-d, --dedup", dest="dedup", default=True,
                                   help="Multiple requests of one device are only counted once.")

tool = VerboseDeviceAnalyzer(core.get_parsed_cli_options().dedup)
core.register_handler(tool)
core.start()
