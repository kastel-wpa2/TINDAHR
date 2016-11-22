#! /usr/bin/env python

import argparse
import pyshark
import sys
from abc import ABCMeta, abstractmethod
import atexit
import urllib2


class IPacketAnalyzer():
    __metaclass__ = ABCMeta

    @abstractmethod
    def get_display_filter(self):
        pass

    @abstractmethod
    def get_bpf_filter(self):
        pass

    @abstractmethod
    def analyze_packet(self, packet):
        pass

    @abstractmethod
    def on_end(self):
        pass


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


class MgtPacketCounter(IPacketAnalyzer):
    MGT_TYPES_NAMES = [""] * 25
    _counter = [0] * 25

    def __init__(self):
        self.MGT_TYPES_NAMES[0] = "Association request"
        self.MGT_TYPES_NAMES[1] = "Association response"
        self.MGT_TYPES_NAMES[4] = "Probe request"
        self.MGT_TYPES_NAMES[5] = "Probe response"
        self.MGT_TYPES_NAMES[8] = "Beacon"
        self.MGT_TYPES_NAMES[11] = "Authentification"
        self.MGT_TYPES_NAMES[12] = "Deauthentification"

        print "Running MgtPacketCounter"

    def get_display_filter(self):
        return "wlan.fc.type == 0"

    def get_bpf_filter(self):
        return "type mgt"

    def analyze_packet(self, packet):
        tipe = packet["WLAN"].fc_subtype.int_value
        self._counter[tipe] += 1

        sys.stdout.write("\rDeauthentification packets: " + str(self._counter[
                         12]) + " | Probe Requests: " + str(self._counter[4]) + " | Beacons: " + str(self._counter[8]))
        sys.stdout.flush()

    def on_end(self):
        for (idx, count) in enumerate(self._counter):
            if count == 0:
                continue
            print self.MGT_TYPES_NAMES[idx] + ":\t " + str(count)


class DeauthCounter(IPacketAnalyzer):
    _counter = [0] * 25
    _counter_reason_code = [0] * 536  # according to IEEE spec

    def __init__(self):
        print "Running DeauthCounter"

    def get_display_filter(self):
        return "wlan.fc.type == 0"  # Mgt frame

    def get_bpf_filter(self):
        return "type mgt"

    def analyze_packet(self, packet):
        tipe = packet["WLAN"].fc_subtype.int_value
        self._counter[tipe] += 1

        if packet["WLAN"].fc_subtype.int_value == 12:
            reason_code = packet["WLAN_MGT"].fixed_reason_code.int_value
            if reason_code <= 535:
                self._counter_reason_code[reason_code] += 1

        sys.stdout.write("\rDeauthentification packets: " + str(self._counter[
                         12]) + " | Probe Requests: " + str(self._counter[4]) + " | Beacons: " + str(self._counter[8]))
        sys.stdout.flush()

    def on_end(self):
        for (idx, count) in enumerate(self._counter_reason_code):
            if count == 0:
                continue
            print str(idx) + ":\t " + str(count)


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
            print key + " (" + self._lookup_vendor(key) + "): " + str(val["with_ssid"]) + " | " + str(val["broadcast"])

    def _lookup_vendor(self, vendor):
        try:
            return urllib2.urlopen("http://api.macvendors.com/" + vendor).read()
        except Exception:
            return "N.A."


class WifiAnalyzer():

    def __init__(self, packet_analyzer):
        assert issubclass(type(packet_analyzer), IPacketAnalyzer)
        self._packet_analyzer = packet_analyzer

        atexit.register(self._packet_analyzer.on_end)

    def read_from_file(self, filename):
        try:
            cap = pyshark.FileCapture(
                filename, display_filter=self._packet_analyzer.get_display_filter())
        except Exception as ex:
            raise Exception("Could not open file '" +
                            options.filename + "'", ex)

        print "Reading from file..."

        for packet in cap:
            self._process_packet(packet)

    def read_live(self, interface):
        print "Reading from live capture..."
        capture = pyshark.LiveCapture(
            interface=interface, bpf_filter=self._packet_analyzer.get_bpf_filter())

        for packet in capture.sniff_continuously():
            self._process_packet(packet)

    def _process_packet(self, packet):
        self._packet_analyzer.analyze_packet(packet)


parser = argparse.ArgumentParser()
parser.add_argument("--ssid_catcher", dest="ssid_catcher_mode",
                    action='store_true', help="Run the SSID-Catcher")
parser.add_argument("--type_counter", dest="mgt_type_counter_mode",
                    action='store_true', help="Run subtype counter")
parser.add_argument("--verbose_devices", dest="verbose_devices_mode",
                    action='store_true', help="Run verbose devices detector")


parser.add_argument("-f, --file", dest="filename", default="",
                    help="PCAP file to load", metavar="FILE")
parser.add_argument("-l, --live", dest="interface", default="",
                    help="Live interface to use", metavar="LIVE_INTERFACE")
parser.add_argument("--filter", dest="filter", default=None,
                    help="Filter used during capturing/parsing PCAP file")

options = parser.parse_args()

tool = None
if options.mgt_type_counter_mode:
    tool = DeauthCounter()
elif options.verbose_devices_mode:
    tool = VerboseDeviceAnalyzer()
else:
    tool = SSIDCatcher()

instance = WifiAnalyzer(tool)

if options.filename != "":
    instance.read_from_file(options.filename)
else:
    instance.read_live(options.interface)
