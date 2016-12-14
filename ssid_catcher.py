#! /usr/bin/env python

import sys
import os
from analyzr_core import *
import re


class SSIDCatcher(IPacketAnalyzer):
    
    def __init__(self, mac_filter):
        print "Running SSIDCatcher"
        self._mac_filter = mac_filter
        self._probe_requests = {}

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

		wlan.sa += " (" + AnalyzrCore.lookup_vendor_by_mac(wlan.sa) + ")"

		if wlan.sa not in self._probe_requests:
			self._probe_requests[wlan.sa] = set()
        
		if(self._new_entry_added(wlan.sa, ssid)):
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
