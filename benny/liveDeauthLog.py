import pyshark
import time


capture = pyshark.LiveCapture(interface='wlan0mon', bpf_filter='subtype deauth')
start = time.time()
for packet in capture.sniff_continuously():
	packageCount += 1
	current = time.time()
	deauthsPerMinute = packageCount/(current-start) * 60
	source = packet['WLAN'].sa
	receiver = packet['WLAN'].ra
	reason = packet['WLAN_MGT']._all_fields['wlan_mgt.fixed.reason_code']
	print 'Source/Sender address: ', source, 'Destination/Receiver address: ', receiver, ' Reason Code: ', reason
	print 'Deauthentifications per minute: ', deauthsPerMinute
