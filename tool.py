#! /usr/bin/env python

import sys
import os
from analyzr_core import *
import re
import threading
import time


class ConnectionTupel():

    def __init__(self, sa, da, channel):
        self.sa = sa
        self.da = da
        self.channel = channel

    def swap_addresses(self):
        tmp = self.sa
        self.sa = self.da
        self.da = tmp

    def __hash__(self):
        return hash(self.sa) ^ hash(self.da) ^ hash(self.channel)

    def __eq__(self, other):
        return ((self.da == other.da and self.sa == other.sa) or (self.da == other.sa and self.sa == other.da)) and self.channel == other.channel

    def __str__(self):
        return "%s <-> %s (channel %s)" % (self.sa, self.da, self.channel)


class ConnectionsList():

    def __init__(self, on_new_handler, on_expired_handler):
        self._list = dict()
        self._on_new = on_new_handler
        self._on_expired = on_expired_handler

        def threadFn():
            while True:
                time.sleep(20)
                self._check_for_expired()

        t = threading.Thread(target=threadFn)
        t.daemon = True
        t.start()

    def add(self, sa, da, channel):
        tupel = ConnectionTupel(sa, da, channel)

        new = tupel in self._list

        self._list[tupel] = time.time()  # timestamp in seconds

        if new:
            self._on_new(sa, da, channel)

        return new

    def _check_for_expired(self):
        now = time.time()

        for tupel, ts in self._list.items():
            if ts + 20 < now:
                del self._list[tupel]
                self._on_expired(tupel.sa, tupel.da, tupel.channel)

    def __iter__(self):
        return self.next()

    def next(self):
        for tupel in self._list:
            yield tupel


class Tool(IPacketAnalyzer):

    def __init__(self, mac_filter, use_cli, port, analyzr_core):
        print "Running SSIDCatcher"
        self._mac_filter = mac_filter
        self._con_list = ConnectionsList(
            self._new_entry_added, self._entry_expired)
        self._analyzr_core = analyzr_core
        self._ssid_map = dict()

        if use_cli:
            t = threading.Thread(target=self._refresh_cli)
            t.daemon = True
            t.start()

    def get_display_filter(self):
        # type of data packages (2), we are just interested in actual connections
        # still we need some mgmt frames (probe response (5) and beacon frames (8)) in order to resolve mac addresses to SSIDs
        return "wlan.fc.type == 2 or wlan.fc.type_subtype == 5 or wlan.fc.type_subtype == 8"

    def get_bpf_filter(self):
        # according to https://linux.die.net/man/7/pcap-filter (search for
        # "type wlan_type")
        return "type data or subtype probe-resp or subtype beacon"

    def analyze_packet(self, packet, channel):
        wlan = packet["WLAN"]

        # skip broadcasting garbage
        if wlan.da == "ff:ff:ff:ff:ff:ff" or wlan.sa == "ff:ff:ff:ff:ff:ff":
            return

        if self._mac_filter != None and re.match(self._mac_filter, str(wlan.sa)) == None and re.match(self._mac_filter, str(wlan.da)) == None:
            return

        tipe = int(packet["WLAN"].fc_type)
        
        # Handle mgmt frames
        if tipe == 0:
            ssid = packet["WLAN_MGT"].ssid

            # Broadcast, we skip this
            if ssid == "SSID: ":
                return

            self._ssid_map[wlan.sa] = ssid
            return

        # Handle data frames
        self._con_list.add(wlan.sa, wlan.da, channel)

    def _new_entry_added(self, sa, da, channel):
        pass

    def _entry_expired(self, sa, da, channel):
        pass

    def _refresh_cli(self):
        while True:
            os.system("clear")
            print "Items in ssid map: " + str(len(self._ssid_map)) + " | Listening on channel: " + str(self._analyzr_core.current_channel)

            for tupel in self._con_list:
                if tupel.sa in self._ssid_map:
                    tupel.swap_addresses()

                print tupel.sa + " <-> " + tupel.da + " (" + self._ssid_map.get(tupel.da, "n.a.") + ") (channel " + str(tupel.channel) + ")"

            time.sleep(1)

    def on_end(self):
        pass


core = AnalyzrCore(channel_hopping=True)

core.get_arg_parser().add_argument("--mac", dest="mac_filter", default=None,
                                   help="Filter by mac address of sender")
core.get_arg_parser().add_argument("--port", dest="port", default=None,
                                   help="Port for webserver to listen to")
core.get_arg_parser().add_argument("--cli", dest="use_cli", action="store_true", default=False,
                                   help="Use command line interface instead of web ui")

cli_options = core.get_parsed_cli_options()
tool = Tool(cli_options.mac_filter, cli_options.use_cli, cli_options.port, core)
core.register_handler(tool)
core.start(force_live_capture=True)
