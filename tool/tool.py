#! /usr/bin/env python

import sys
import os
from analyzr_core import *
import re
import threading
import time
import copy
from deauth_jammer import DeauthJammer

from webserver import WebAdapter


class ConnectionTupel():

    def __init__(self, sa, da, channel, ssid="n.a."):
        self.sa = sa
        self.da = da
        self.channel = channel
        self.ts = time.time()
        self.ssid = ssid

    def swap_addresses(self):
        tmp = self.sa
        self.sa = self.da
        self.da = tmp

    def __hash__(self):
        # We assume that channel isn't important because adjacent channels
        # interfere and so we catch twice times the same connection when
        # listening on close by channels
        return hash(self.sa) ^ hash(self.da)

    def __eq__(self, other):
        return self.da == other.da and self.sa == other.sa

    def __str__(self):
        age = round(time.time() - self.ts, 1)
        return "%s <-> %s (%s) (channel %s) (age %ss)" % (self.sa, self.da, self.ssid, self.channel, age)


class ConnectionsList():

    def __init__(self):
        self._list = set()
        self._ssid_map = dict()

        def threadFn():
            while True:
                time.sleep(10)
                self._check_for_expired()

        t = threading.Thread(target=threadFn)
        t.daemon = True
        t.start()

    def add(self, sa, da, channel):
        tupel = ConnectionTupel(sa, da, channel)

        new = tupel in self._list

        self._list = set([tupel]).union(self._list)  # timestamp in seconds

        return new

    def _check_for_expired(self):
        now = time.time()

        # we need this copy otherwise we change the size by deleting elements
        # during iterating
        shallow_copy = copy.copy(self._list)

        for tupel in shallow_copy:
            if tupel.ts + 20 < now:
                self._list.remove(tupel)

    def __iter__(self):
        return self.next()

    def add_ssid_for_mac(self, mac, ssid):
        new = mac in self._ssid_map

        self._ssid_map[mac] = ssid

        return new

    def next(self):
        # Create a shallow copy to prevent race conditions caused by another thread cleaning
        # up expired entries and therefore causing a size-change during
        # iteration of dictionary
        shallow_copy = copy.copy(self._list)

        for tupel in shallow_copy:
            if tupel.ssid == "n.a.":
                tupel.ssid = self._ssid_map.get(tupel.da, "n.a.")

            yield tupel

    def get_as_popo(self):
        popo = []
        now = time.time()

        for tupel in self._list:
            if tupel.ssid == "n.a.":
                tupel.ssid = self._ssid_map.get(tupel.da, "n.a.")

            popo.append({
                "sa": tupel.sa,
                "sa_vendor": AnalyzrCore.lookup_vendor_by_mac(tupel.sa),
                "da": tupel.da,
                "da_vendor": AnalyzrCore.lookup_vendor_by_mac(tupel.da),
                "ssid": tupel.ssid,
                "channel": tupel.channel,
                "age": round(now - tupel.ts, 1)
            })

        return popo


class Tool(IPacketAnalyzer):

    def __init__(self, mac_filter, use_cli, port, analyzr_core):
        print "Running 'Tool'"
        self._mac_filter = mac_filter
        self._con_list = ConnectionsList()
        self._analyzr_core = analyzr_core
        self._ssids_found = 0

        if use_cli:
            t = threading.Thread(target=self._refresh_cli)
            t.daemon = True
            t.start()
        else:
            adapter = WebAdapter(
                self._con_list, self.run_deauth_attack, port=1337)
            try:
                adapter.start()
            except KeyboardInterrupt:
                pass

    def get_display_filter(self):
        # type of data packages (2), we are just interested in actual connections
        # still we need some mgmt frames (probe response (5) and beacon frames
        # (8)) in order to resolve mac addresses to SSIDs
        return "wlan.fc.type == 2 or wlan.fc.type_subtype == 5 or wlan.fc.type_subtype == 8"

    def get_bpf_filter(self):
        # according to https://linux.die.net/man/7/pcap-filter (search for
        # "type wlan_type")
        # subtype probe-ressp or subtype beacon implicitly enforce type mgmt
        return "type data or subtype probe-resp or subtype beacon"

    def analyze_packet(self, packet, channel):
        # (Almost) Every single packet contains the bssid, the MAC address of the access point sending
        # or receiving this package. We need "da" to be the address of the access point, by this we know in
        # which direction this package has been sent. But the position of the bssid in the frame varies
        # depending on the origin and destination of the packet. It can be inferred looking at "To DS"
        # and "From DS" bits. So we actual do not name BSSID in the following, but it is already what
        # we extract from the packet "To DS" and "From DS" can be checked
        # here: http://einstein.informatik.uni-oldenburg.de/rechnernetze/frame.htm
        DS = packet.FCfield & 0x3
        to_DS = DS & 0x1 != 0
        from_DS = DS & 0x2 != 0

        # implicit case !to_DS and !from_DS
        da = packet.addr3
        sa = packet.addr2

        if to_DS and from_DS:
            # This page clarifies that:
            # https://technet.microsoft.com/en-us/library/cc757419(v=ws.10).aspx
            da = packet.addr1
            sa = packet.addr4
        elif to_DS and not from_DS:
            da = packet.addr1
        elif not to_DS and from_DS:
            da = packet.addr2
            sa = packet.addr1

        # Drop packets caused by IPv6 neighbour discovery (as described
        # here: http://en.citizendium.org/wiki/Neighbor_Discovery)
        if da.startswith("33:33") or sa.startswith("33:33"):
            return

        # skip broadcasting garbage (like caused by IPv4's ARP discovery)
        if da == "ff:ff:ff:ff:ff:ff" or sa == "ff:ff:ff:ff:ff:ff":
            return

        if self._mac_filter is not None and re.match(self._mac_filter, sa) is None and re.match(self._mac_filter, da) is None:
            return

        tipe = int(packet.type)

        # Handle mgmt frames
        if tipe == 0:
            ssid = packet.info

            # Broadcast, we skip this
            if not ssid:
                return

            mac_had_no_known_ssid_before = self._con_list.add_ssid_for_mac(
                da, ssid)
            self._ssids_found += 1 if mac_had_no_known_ssid_before else 0
            return

        # Handle data frames
        self._con_list.add(sa, da, channel)

    def _refresh_cli(self):
        while True:
            os.system("clear")
            print "Items in ssid map: " + str(self._ssids_found) + " | Listening on channel: " + str(self._analyzr_core.current_channel)

            for tupel in self._con_list:
                print tupel

            time.sleep(1)

    def on_end(self):
        pass

    def run_deauth_attack(self, target_mac, ap_mac, channel, packet_count, capture_handshake):
        iface = self._analyzr_core.iface
        jammer = DeauthJammer(ap_mac, iface)
        return jammer.jam(target_mac, packet_count=packet_count, capture_handshake=capture_handshake, channel=channel)


core = AnalyzrCore(channel_hopping=True)

core.get_arg_parser().add_argument("--mac", dest="mac_filter", default=None,
                                   help="Filter by mac address of sender")
core.get_arg_parser().add_argument("--port", dest="port", default=None,
                                   help="Port for webserver to listen to")
core.get_arg_parser().add_argument("--cli", dest="use_cli", action="store_true", default=False,
                                   help="Use command line interface instead of web ui")

cli_options = core.get_parsed_cli_options()
tool = Tool(cli_options.mac_filter,
            cli_options.use_cli, cli_options.port, core)
core.register_handler(tool)
core.start(force_live_capture=True)
