#! /usr/bin/env bash
tshark -i wlan0mon -f "type mgt" -w $(date +%s).pcap
