import pyshark
capture = pyshark.LiveCapture(interface = 'wlan0mon', bpf_filter = 'subtype probereq', output_file = 'tdump1.pcap')
capture.sniff(timeout = 10)
