#! /usr/bin/env python

import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from analyzr_core import *


class DeauthCounter(IPacketAnalyzer):
    _counter = [0] * 25
    _counter_reason_code = [0] * 536  # according to IEEE spec
    reason_missing = 0

    def __init__(self):
        print "Running DeauthCounter"

    def get_bpf_filter(self):
        return "type mgt"

    def analyze_packet(self, packet, channel):
        subtype = packet.subtype
        self._counter[subtype] += 1

        if subtype == 12:
            reason_code = 1
            if "reason" in packet and packet.reason <= 535:
                reason_code = packet.reason
            else:
                self.reason_missing += 1

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
            print "Reason missing: ", str(self.reason_missing)

deauth_counter = DeauthCounter()
core = AnalyzrCore(deauth_counter)
core.start()