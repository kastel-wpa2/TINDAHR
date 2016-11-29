import pyshark
capture = pyshark.LiveCapture(interface = 'wlan0mon', bpf_filter = 'subtype probereq')
for packet in capture.sniff_continuously(packet_count = 30):
	print packet['WLAN'].pretty_print()
	print '======================================='
