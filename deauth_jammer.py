#! /usr/bin/env python

import threading
import atexit

class DeauthJammer(object): 
    def __init__(self, access_point):
        self._access_point = access_point
        self._threads = []
        atexit.register(self._on_end)

    def jam(self, packet_count=1, targets=None):
        if(not targets):
            return

        for target in targets:
            jamThread = threading.Thread(target=self._deauth_target, args=(packet_count, target), kwargs={})
            self._threads.append(jamThread)
            jamThread.start()
        
    def _deauth_target(self, packet_count, target):
        print target

    def _on_end(self):
        for thread in self._threads:
            thread.join



jammer = DeauthJammer("ssid")
jammer.jam(packet_count = 3, targets=["1", "2"])