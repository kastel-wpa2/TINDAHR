import pyshark
capture = pyshark.LiveCapture(interface='wlan0mon', bpf_filter='subtype probereq')
for packet in capture.sniff_continuously():
	if packet['WLAN_MGT'].ssid != 'SSID: ':
		print 'Device: ', packet['WLAN'].sa, ' SSID: ', packet['WLAN_MGT'].ssid
