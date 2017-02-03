import argparse
import atexit
import sys
import os
import time
import threading
from subprocess import Popen, PIPE
from abc import ABCMeta, abstractmethod
import types
import scapy.all as scapy
import vendor.manuf.manuf.manuf as manuf


class IPacketAnalyzer():
    __metaclass__ = ABCMeta

    @abstractmethod
    def get_bpf_filter(self):
        pass

    @abstractmethod
    def analyze_packet(self, packet, channel):
        pass

    @abstractmethod
    def on_end(self):
        pass


class AnalyzrCore():
    _vendor_lookup_cache = dict()
    _manuf = manuf.MacParser(manuf_name=os.path.dirname(
        os.path.realpath(__file__)) + "/vendor/manuf/manuf/manuf")

    def __init__(self, packet_analyzer=None, channel_hopping=False):
        if packet_analyzer != None:
            self.register_handler(packet_analyzer)

        self._arg_parser = argparse.ArgumentParser()
        self._arg_parser.add_argument("-f, --file", dest="filename", default="",
                                      help="PCAP file to load", metavar="FILE")
        self._arg_parser.add_argument("-l, --live", dest="interface", default="", nargs="?",
                                      help="Live interface to use", metavar="LIVE_INTERFACE")
        self._arg_parser.add_argument("--filter", dest="filter", default=None,
                                      help="Filter used during capturing/parsing PCAP file")
        self._arg_parser.add_argument("-c, --channel", dest="channel", default=0,
                                      help="Channel on which shall be listened in case of live capture", type=types.IntType)

        self._parsed_options = None

        self.current_channel = None
        self._channel_hopping = channel_hopping

    def register_handler(self, packet_analyzer):
        assert issubclass(type(packet_analyzer), IPacketAnalyzer)
        self._packet_analyzer = packet_analyzer

        atexit.register(self._packet_analyzer.on_end)

    def get_arg_parser(self):
        return self._arg_parser

    def get_parsed_cli_options(self):
        if self._parsed_options == None:
            self._parsed_options = self._arg_parser.parse_args()

        return self._parsed_options

    def start(self, force_live_capture=False):
        options = self.get_parsed_cli_options()

        bpf_filter = self._packet_analyzer.get_bpf_filter()

        try:
            if options.filename != "" and not force_live_capture:
                self.read_from_file(options.filename, bpf_filter)
            else:
                self.read_live(options.interface, options.channel, bpf_filter)
        except KeyboardInterrupt:
            print "Catched keyboard interrupt: exiting application."
            sys.exit()

    def read_from_file(self, filename, bpf_filter):
        try:
            print "Reading from file..."
            filename = os.path.abspath(filename)
            scapy.sniff(offline=filename, filter=bpf_filter, prn=self._process_packet)
        except Exception as ex:
            raise Exception("Could not open file '" + filename + "'", ex)

        print "Reading from file..."

    def read_live(self, interface, channel, bpf_filter):
        self._kill_processes()

        if interface is None or not interface:
            interface = self._select_interface(False)

        self.iface = interface

        print "Reading from live capture..."

        if self._channel_hopping and channel == 0:
            channel = 1
        else:
            self._channel_hopping = False

        AnalyzrCore.set_channel(interface, channel)
        self.current_channel = channel

        if self._channel_hopping:
            self._start_channel_hopping(interface)

        scapy.sniff(iface=interface, filter=bpf_filter,
                    prn=self._process_packet)

    def _kill_processes(self):
        print "Killing processes which may interfere the scanning process."
        Popen(["sudo", "airmon-ng", "check", "kill"]).communicate()

    def _select_from_airodump(self):
        interface = self._select_interface(False)
        try:
            airodump = Popen(["sudo", "airodump-ng", interface]).communicate()
        except KeyboardInterrupt:
            print "Placeholder"

    def _select_interface(self, second_try):
        iwconfig = Popen(["iwconfig"], stdout=PIPE,
                         stderr=open(os.devnull, "w"))
        monitor = []
        regular = []
        for line in iwconfig.communicate()[0].split('\n'):
            if len(line) is 0:
                continue
            if ord(line[0]) != 32:
                interface = line[:line.find(' ')]
                # if we find the string Mode:Monitor put the adapter in the
                # monitor array
                if line.find('Mode:Monitor') != -1:
                    monitor.append(interface)
                else:
                    regular.append(interface)

        if len(monitor) is 0:
            if len(regular) is 0:
                sys.stderr.write(
                    "No interface with wireless extensions were found.")
                sys.stderr.flush()
                raise Exception
            print "No interface in monitor mode found. Following interfaces were found:"
            print regular
            if second_try:
                sys.stderr.write("Even after enabling monitor mode on a specific device,"
                                 + "there was no device found with monitor mode activated.")
                sys.stderr.flush()

            else:
                interface = self._enable_monitor_mode(regular)
        else:
            print "Following interfaces in monitor mode found:"
            print monitor
            print "Picking first interface: ", monitor[0]
            interface = monitor[0]

        return interface

    def _enable_monitor_mode(self, interfaces):
        print "Enabling monitor mode on first interface: ", interfaces[0]
        Popen(["airmon-ng", "start", interfaces[0]], stdout=PIPE,
              stderr=open(os.devnull, "w")).communicate()
        print "Checking for interfaces again."
        return self._select_interface(True)

    def _process_packet(self, packet):
        self._packet_analyzer.analyze_packet(packet, self.current_channel)

    @staticmethod
    def lookup_vendor_by_mac(vendor):
        if vendor in AnalyzrCore._vendor_lookup_cache:
            return AnalyzrCore._vendor_lookup_cache[vendor]

        resolved = AnalyzrCore._manuf.get_comment(str(vendor))
        if not resolved:
            resolved = "n.a."
        AnalyzrCore._vendor_lookup_cache[vendor] = resolved
        return resolved

    @staticmethod
    def set_channel(interface, channel):
        os.system("iwconfig %s channel %d" % (interface, channel))

    def _start_channel_hopping(self, interface, delay=1):
        def channel_hopper():
            while True:
                for i in range(1, 15):
                    AnalyzrCore.set_channel(interface, i)
                    self.current_channel = i
                    time.sleep(delay)

        t = threading.Thread(target=channel_hopper)
        t.daemon = True
        t.start()
