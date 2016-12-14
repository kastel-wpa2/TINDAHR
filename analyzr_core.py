import argparse
import pyshark
import atexit
import urllib2
import sys
import subprocess
import os
from subprocess import Popen, PIPE
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
        self._arg_parser.add_argument("-l, --live", dest="interface", default=None, nargs = "?",
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

        try: 
            if options.filename != "":
                self.read_from_file(options.filename)
            else:
                self.read_live(options.interface)
        except KeyboardInterrupt:
            print "Catched keyboard interrupt: exiting application."
            sys.exit()

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
        if(interface == None or interface == ""):
            interface = self._select_interface(False)
        
        print "Reading from live capture..."
        capture = pyshark.LiveCapture(
            interface=interface, bpf_filter=self._packet_analyzer.get_bpf_filter())

        for packet in capture.sniff_continuously():
            self._process_packet(packet)

    def _select_from_airodump(self):
        interface = self._select_interface(False);
        try:
            airodump = Popen(["sudo", "airodump-ng", interface]).communicate()
        except KeyboardInterrupt:
            print "Placeholder"

    def _select_interface(self, secdond_try):
        iwconfig = Popen(["iwconfig"], stdout=PIPE, stderr=open(os.devnull, "w"))
        monitor = []
        regular = []
        for line in iwconfig.communicate()[0].split('\n'):
            if len(line) == 0: 
                continue
            if ord(line[0]) != 32:  
                interface = line[:line.find(' ')] 
                if line.find('Mode:Monitor') != -1: #if we find the string Mode:Monitor put the adapter in the monitor array
                    monitor.append(interface)
                else:
                    regular.append(interface)
        
        if(len(monitor) == 0):
            if(len(regular) == 0):
                sys.stderr.write("No interface with wireless extensions were found.")
                sys.stderr.flush()  
                raise Exception
            print "No interface in monitor mode found. Following interfaces were found:"
            print regular
            if(secdond_try):
                sys.stderr.write("Even after enabling monitor mode on a specific device, there was no device found with monitor mode activated.")
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
        airmon = Popen(["airmon-ng", "start", interfaces[0]], stdout=PIPE, stderr=open(os.devnull, "w"))
        airmon.communicate()
        print "Checking for interfaces again."
        return self._select_interface(True)

    def _process_packet(self, packet):
        self._packet_analyzer.analyze_packet(packet)

    @staticmethod
    def lookup_vendor_by_mac(vendor):
        try:
            return urllib2.urlopen("http://api.macvendors.com/" + vendor).read()
        except Exception:
            return "N.A."
