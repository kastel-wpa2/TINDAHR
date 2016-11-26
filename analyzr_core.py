import argparse
import pyshark
import atexit
import urllib2
from abc import ABCMeta, abstractmethod


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


class AnalyzrCore():

    def __init__(self, packet_analyzer):
        assert issubclass(type(packet_analyzer), IPacketAnalyzer)
        self._packet_analyzer = packet_analyzer

        atexit.register(self._packet_analyzer.on_end)

        self._arg_parser = argparse.ArgumentParser()
        self._arg_parser.add_argument("-f, --file", dest="filename", default="",
                                      help="PCAP file to load", metavar="FILE")
        self._arg_parser.add_argument("-l, --live", dest="interface", default="",
                                      help="Live interface to use", metavar="LIVE_INTERFACE")
        self._arg_parser.add_argument("--filter", dest="filter", default=None,
                                      help="Filter used during capturing/parsing PCAP file")

        self._parsed_options = None

    def get_arg_parser(self):
        return self._arg_parser

    def get_parsed_cli_options(self):
        if self._parsed_options == None:
            self._parsed_options = self._arg_parser.parse_args()

        return self._parsed_options

    def start(self):
        options = self.get_parsed_cli_options()

        if options.filename != "":
            self.read_from_file(options.filename)
        else:
            self.read_live(options.interface)

    def read_from_file(self, filename):
        try:
            cap = pyshark.FileCapture(
                filename, display_filter=self._packet_analyzer.get_display_filter())
        except Exception as ex:
            raise Exception("Could not open file '" +
                            filename + "'", ex)

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

    @staticmethod
    def lookup_vendor_by_mac(vendor):
        try:
            return urllib2.urlopen("http://api.macvendors.com/" + vendor).read()
        except Exception:
            return "N.A."
