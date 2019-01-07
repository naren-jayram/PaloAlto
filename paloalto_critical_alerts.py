"""
Objective: To export Critical alerts (Threat logs, since last one hour) from PaloAlto; And to send exported alerts as an attachment via email to appropriate Email ID.

Pre-Requisites:
1. Clone the repo, pan-python: https://github.com/kevinsteves/pan-python/ 
2. Access to PaloAlto Panorama

Usage: 
    1. Place this script in the 'bin' directory of the repo.
    2. python paloalto_critical_alerts.py

Output:
Critical alerts from PaloAlto Threat logs will be exported to <Critical_Alerts_Last_Hour.csv> file 

Note: 1. In this case, we are pulling "Threat" logs from PaloAlto. You can change the log type as per your needs. ex: URL Filtering, Traffic 
      2. PaloAlto API key can be generated this way
         python panxapi.py -l <username>:<password> -h <paloAlto Hostname/ IP> -k
      3. I know its a bad practise to include credentials within a script. Please use .netrc file concept to deal with credentials in a secure way
"""

import csv
import json
import commands
import datetime
import time
import sys
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from email.MIMEBase import MIMEBase
from email import encoders
import base64

# Configuration
paloalto_host = " "                     # PaloAlto Hostname/ IP
paloalto_api_key = " "                  # Your PaloAlto API key comes here
log_type = "threat"                     # PaloAlto log type
severity = "critical"                   # Alert Severity  
num_logs = 500                          #Max number of logs to retreive
email_server = "smtp.office365.com"     # Email Server
email_server_port = 587                 # Email Server Port
email_password = " "                    # Sender's Email Password
from_address = " "                      # Your Email ID
to_address = " "                        # To Email ID
# End of Configuration

cur_time = datetime.datetime.utcnow()
last_hour_time = cur_time - datetime.timedelta(hours = 1)
time_value = last_hour_time.strftime('%Y/%m/%d %H:%M:%S')
script = "panxapi.py"
query_filter = "receive_time geq '%s' AND severity eq '%s'" % (time_value, severity)
command = "python %s -h %s -K '%s' --log %s -jr --nlogs %d --filter \"%s\" > critical_alerts.json" % (script, paloalto_host, paloalto_api_key, log_type, num_logs, query_filter)
output = commands.getoutput(command)

with open('critical_alerts.json') as data_file:
    data = json.load(data_file)

alert_details = data['log']['logs'].get('entry')

if not alert_details:
    print "No Alerts! Exiting..."
    sys.exit()

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
      			   'dg_hier_level_4', 'vsys_name', 'device_name', 'file_url'
              ]


with open('Critical_Alerts_Last_Hour.csv', 'w+') as ids_alert:
    csvwriter = csv.writer(ids_alert)
    csvwriter.writerow(header_list)
    for alert in alert_details:
        row_data = []
        for header in header_list:
            if isinstance(alert.get(headers.get(header)), dict):
                data = alert.get(headers.get(header))['code']
            else:
                data = alert.get(headers.get(header))
            row_data.append(data)
        csvwriter.writerow(row_data)


#Below code helps to send email with attachment
msg = MIMEMultipart()
msg['From'] = from_address
msg['To'] = to_address
msg['Subject'] = "Critical Alerts: Last 60 Minutes!"
body = "Hello Team, \n\n Kindly analyze the attached PaloAlto critical alerts on priority!"
msg.attach(MIMEText(body, 'plain'))
filename = "Critical_Alerts_Last_Hour.csv"

attachment = open("Critical_Alerts_Last_Hour.csv", "r")
part = MIMEBase('application', 'octet-stream')
part.set_payload((attachment).read())
encoders.encode_base64(part)
part.add_header('Content-Disposition', "attachment; filename= %s" % filename)
msg.attach(part)

server = smtplib.SMTP(email_server, email_server_port)
server.starttls()
server.login(from_address, email_password)
text = msg.as_string()
server.sendmail(from_address, to_address, text)
server.quit()
