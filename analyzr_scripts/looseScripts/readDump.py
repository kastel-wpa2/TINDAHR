import requests
import pyshark
capture = pyshark.FileCapture(input_file = 'tdump0')
for packet in capture:
	if packet['WLAN_MGT'].ssid != 'SSID: ':
		print 'Device: ', packet['WLAN'].sa, ' SSID: ', packet['WLAN_MGT'].ssid
		r = requests.get('http://api.macvendors.com/' + packet['WLAN'].sa)
		print r.text
