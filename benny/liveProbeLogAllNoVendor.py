import pyshark
capture = pyshark.LiveCapture(interface='wlan0mon', bpf_filter='subtype probereq')
for packet in capture.sniff_continuously():
	ssid = 'Broadcast'
	if packet['WLAN_MGT'].ssid != 'SSID: ':
		ssid = packet['WLAN_MGT'].ssid	
	print 'Device: ', packet['WLAN'].sa, ' SSID: ', ssid
