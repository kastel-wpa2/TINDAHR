import pyshark
import requests
capture = pyshark.LiveCapture(interface='wlan0mon', bpf_filter='subtype probereq')
for packet in capture.sniff_continuously():
	if packet['WLAN_MGT'].ssid != 'SSID: ':
		requestText = "http://api.macvendors.com/" + packet['WLAN'].sa
		r = requests.get(requestText)
		print 'Device: ', packet['WLAN'].sa, 'Device vendor: ', r.text, ' SSID: ', packet['WLAN_MGT'].ssid
