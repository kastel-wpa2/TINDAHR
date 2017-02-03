#! /usr/bin/env python

import sys
import os
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from analyzr_core import *


class SSIDCatcher(IPacketAnalyzer):

    def __init__(self, mac_filter):
        print "Running SSIDCatcher"
        self._mac_filter = mac_filter
        self._probe_requests = {}

    def get_bpf_filter(self):
        return "subtype probereq"

    def analyze_packet(self, packet, channel):
        ssid = packet.info

        sa = packet.addr2

        # Broadcast, we skip this
        if not ssid:
            return

        if self._mac_filter != None and re.match(self._mac_filter, sa) == None:
            return

        sa += " (" + AnalyzrCore.lookup_vendor_by_mac(sa) + ")"

        if sa not in self._probe_requests:
            self._probe_requests[sa] = set()

        if(self._new_entry_added(sa, ssid)):
            self._refresh()

    def _new_entry_added(self, source, ssid):
        source_key = self._probe_requests[source]
        return len(source_key) != (source_key.add(ssid) or len(source_key))

    def _refresh(self):
        os.system("clear")
        indent = 0
        for station in self._probe_requests:
            if indent < len(station):
                indent = len(station)

        for station in sorted(self._probe_requests):
            temp_station = station.ljust(indent)
            line = temp_station + ": \t"
            for ssid in self._probe_requests[station]:
                line += "\'" + ssid + "\', "
            print line[:-2]

    def on_end(self):
        pass


core = AnalyzrCore()

core.get_arg_parser().add_argument("--mac", dest="mac_filter", default=None,
                                      help="Filter by mac address of sender")

ssid_catcher = SSIDCatcher(core.get_parsed_cli_options().mac_filter)
core.register_handler(ssid_catcher)
core.start()
