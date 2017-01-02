#! /usr/bin/env python

import sys
from analyzr_core import *


class DeauthCounter(IPacketAnalyzer):
    _counter = [0] * 25
    _counter_reason_code = [0] * 536  # according to IEEE spec

    def __init__(self):
        print "Running DeauthCounter"

    def get_display_filter(self):
        return "wlan.fc.type == 0"  # Mgt frame

    def get_bpf_filter(self):
        return "type mgt"

    def analyze_packet(self, packet, channel):
        subtype = int(packet["WLAN"].fc_subtype)
        self._counter[subtype] += 1

        if int(packet["WLAN"].fc_subtype) == 12:
            reason_code = int(packet["WLAN_MGT"].fixed_reason_code)
            if reason_code <= 535:
                self._counter_reason_code[reason_code] += 1

        sys.stdout.write("\rDeauthentification packets: " + str(self._counter[
                         12]) + " | Probe Requests: " + str(self._counter[4]) + " | Beacons: " + str(self._counter[8]))
        sys.stdout.flush()

    def on_end(self):
        print "\n\n========================"
        for (idx, count) in enumerate(self._counter_reason_code):
            if count == 0:
                continue
            print str(idx) + ":\t " + str(count)

deauth_counter = DeauthCounter() 
core = AnalyzrCore(deauth_counter)
core.start()