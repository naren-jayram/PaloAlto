'''
Objective: To search and export interested logs from PaloAlto UTM (Panorama)

Prerequisites:
1. Clone the repo, pan-python: https://github.com/kevinsteves/pan-python/ 
2. Access to PaloAlto Panorama

Usage: 
    1. Place this script in the 'bin' directory of the repo.
    2. Create a file, <input.txt> and place all the concerned IP addresses here. P.S: One IP per line
    3. python paloalto_search.py

Output:
Interested logs will be exported to <Interested_Traffic.csv> file 

Note: 1. In this case, we are pulling interested "Threat" logs from PaloAlto. You can change the log type as per your needs. ex: url, traffic 
      2. PaloAlto API key can be generated this way
         python panxapi.py -l <username>:<password> -h <paloAlto Hostname/ IP> -k
      3. I know it's a bad practise to include credentials within a script. Please use .netrc file concept to deal with credentials in a secure way
'''


#!/usr/bin/python
import csv
import json
import commands
import datetime
import time
import sys
import base64
import commands
import os

# Configuration
paloalto_host = " "			# PaloAlto Host
api_key = " "				# PaloAlto API Key
log_type = " "				# Log Type. ex: traffic, threat, url
num_logs = 5000				# How many logs to pull?
time_value = " "			# From when you want to pull the logs? ex: 2019/01/02 00:00:00
# End of Configuration


# Read IP Addresses from input file
ip_address_list = []
with open('input.txt','r') as ip:
	ip_address = ip.readlines()
	for ip in ip_address:
		clean_ip = ip.replace(' ', '').replace('\n', '')
		ip_address_list.append(clean_ip)


script = "panxapi.py"


complete_data = []
with open ('Interested_Traffic.json', 'w+') as file:
	for ip in ip_address_list:
		print ip
		api_filter = "receive_time geq '%s' AND addr.dst in '%s'" % (time_value, ip)
		log_cmd = "python %s -h %s -K '%s' --log %s -jr --nlogs %d --filter \"%s\" > specific_traffic.json" % (script, paloalto_host, api_key, log_type, num_logs, api_filter)
		output = commands.getoutput(log_cmd)
		with open("specific_traffic.json") as specific_traffic:
			out = json.load(specific_traffic)
			complete_data.append(out)

	file.write(json.dumps(complete_data))
	os.remove('specific_traffic.json')


	
header_list = ['Domain', 'Receive Time', 'Serial #', 'Type',
               'Threat/Content Type', 'Config Version', 'Generate Time',
               'Source Address', 'Destination Address', 'NAT Source IP',
               'NAT Destination IP', 'Rule', 'Source User', 'Destination User',
               'Application', 'Virtual System', 'Source Zone',
               'Destination Zone', 'Inbound Interface', 'Outbound Interface', 'Log Action', 
			   'Time Logged', 'Session ID', 'Repeat Count', 'Source Port', 'Destination Port', 
			   'NAT Source Port', 'NAT Destination Port', 'Flags', 'IP Protocol', 'Action', 'URL', 
			   'Threat/Content Name', 'Category', 'Severity', 'Direction', 'seqno', 'actionflags', 
			   'Source Country', 'Destination Country', 'cpadding', 'contenttype', 'pcap_id', 
			   'filedigest', 'cloud', 'url_idx', 'user_agent', 'filetype', 'xff', 'referer', 'sender', 
			   'subject', 'recipient', 'reportid', 'dg_hier_level_1', 'dg_hier_level_2', 'dg_hier_level_3',
			   'dg_hier_level_4', 'vsys_name', 'device_name', 'file_url']

headers = {'URL': 'misc', 'cpadding': 'cpadding',
			   'Time Logged': 'time_received',
			   'Source User': 'srcuser' ,'Destination User': 'dstuser',
	           'Config Version': 'config_ver',
	           'Threat/Content Type': 'subtype', 'Log Action': 'logset', 'Domain': 'domain', 
			   'Repeat Count': 'repeatcnt', 'Source Zone': 'from', 'Application': 'app', 
			   'actionflags': 'actionflags', 'Inbound Interface': 'inbound_if',
			   'Receive Time': 'time_received', 'Flags': 'flag-pcap', 'Serial #': 'serial',
			   'Destination Country': 'dstloc', 'Action': 'action', 'NAT Destination Port': 'natdport',
			   'Generate Time': 'time_generated', 'Category': 'category', 'Source Port': 'sport', 
			   'Severity': 'severity', 'IP Protocol': 'proto',  'Destination Address': 'dst', 
			   'NAT Source IP': 'natsrc', 'Captive-Portal': 'captive-portal', 'Destination Zone': 'to',
			   'Source Country': 'srcloc', 'seqno': 'seqno', 'tid': 'tid', 'NAT Destination IP': 'natdst',
			   'Type': 'type', 'NAT Source Port': 'natsport', 'Direction': 'direction',
			   'Outbound Interface':  'outbound_if', 'Source Address': 'src', 'Threat/Content Name': 'threatid',
			   'Receive Time': 'receive_time', 'non-std-dport': 'non-std-dport', 'PCAP_ID': 'pcap_id', 
			   'Virtual System': 'vsys', 'Session ID': 'sessionid', 'Rule': 'rule', 'device_name': 'device_name',
			   'Log ID': 'logid', 'Sub Type': 'subtype', 'Flags': 'flags',  'Destination Port': 'dport', 'url_idx': 'url_idx'
			}


with open('Interested_Traffic.csv', 'w+') as interested_traffic:
	csvwriter = csv.writer(interested_traffic)
	csvwriter.writerow(header_list)

	for data in complete_data:
		traffic_data = data['log']['logs'].get('entry')
		if not traffic_data:
		    print "empty entries"
		    sys.exit()		
		
		for data in traffic_data:
		    row_data = []
		    for header in header_list:
		        if isinstance(data.get(headers.get(header)), dict):
		            interested_data = data.get(headers.get(header))['code']
		        else:
		            interested_data = data.get(headers.get(header))
		        row_data.append(interested_data)
		    csvwriter.writerow(row_data)
	

