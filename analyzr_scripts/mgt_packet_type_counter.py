#! /usr/bin/env python

import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from analyzr_core import *


class MgtPacketCounter(IPacketAnalyzer):
    MGT_TYPES_NAMES = [""] * 25
    _counter = [0] * 25

    def __init__(self):
        self.MGT_TYPES_NAMES[0] = "Association request".ljust(20)
        self.MGT_TYPES_NAMES[1] = "Association response".ljust(20)
        self.MGT_TYPES_NAMES[4] = "Probe request".ljust(20)
        self.MGT_TYPES_NAMES[5] = "Probe response".ljust(20)
        self.MGT_TYPES_NAMES[8] = "Beacon".ljust(20)
        self.MGT_TYPES_NAMES[11] = "Authentification".ljust(20)
        self.MGT_TYPES_NAMES[12] = "Deauthentification".ljust(20)

        print "Running MgtPacketCounter"

    def get_bpf_filter(self):
        return "type mgt"

    def analyze_packet(self, packet, channel): 
        self._counter[packet.subtype] += 1

        sys.stdout.write("\rDeauthentification packets: " + str(self._counter[
                         12]) + " | Probe Requests: " + str(self._counter[4]) + " | Beacons: " + str(self._counter[8]))
        sys.stdout.flush()

    def on_end(self):
        print "\n\n========================"

        for (idx, count) in enumerate(self._counter):
            if count == 0:
                continue
            if self.MGT_TYPES_NAMES[idx] != "":
                prefix = self.MGT_TYPES_NAMES[idx]
            else:
                prefix = ("Code " + str(idx)).ljust(20)
            print prefix + ":\t " + str(count)

mgt_type_counter = MgtPacketCounter()
core = AnalyzrCore(mgt_type_counter)
core.start()
