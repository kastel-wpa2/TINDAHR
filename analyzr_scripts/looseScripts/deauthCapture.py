import pyshark
import argparse
import sys

parser = argparse.ArgumentParser(description='None')
parser.add_argument('output_file', type = str)
args = parser.parse_args()
capture = pyshark.LiveCapture(interface = 'wlan0mon', bpf_filter='subtype deauth', output_file = args.output_file)

try:
	for packet in capture.sniff_continuously():
		source = packet['WLAN'].sa
		receiver = packet['WLAN'].ra
		reason = packet['WLAN_MGT']._all_fields['wlan_mgt.fixed.reason_code']
		print 'Source/Sender address: ', source, 'Destination/Receiver address: ', receiver, ' Reason Code: ', reason
except KeyboardInterrupt:
	sys.exit()