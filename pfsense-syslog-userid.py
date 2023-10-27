#!/usr/bin/python3
import sys
import requests
from lxml import html
import re
import time

import socket
import argparse

### Fill in your firewall IP and port where syslog user-id agent is listening
firewall_ip = "1.2.3.4"
firewall_port = 514

# time in seconds to wait before looping through DHCP leases again
cycle_timer = 30 * 60 ### 30 minute for typical default of 45 min timeout on PANOS

#time between messages to wait before sending (to avoid overloading server)
per_message_delay_timer = 1 ### 1 second should be enough

### Set PFSense URL, username, and password
url  = "https://1.2.3.1/status_dhcp_leases.php" #change url to match your pfsense machine address. Note http or https!
user = 'admin'  #Username for pfSense login
password = 'password' #Password for pfSense login

FACILITY = {
    'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
    'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
    'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
    'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
    'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

LEVEL = {
    'emerg': 0, 'alert':1, 'crit': 2, 'err': 3,
    'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}

### Looks at PFSense DHCP Leases page and gets IP's and populates a list of IP's (ip), Description (username), Mac Address (unused)
### Adapted from: https://gist.github.com/clayrosenthal/9c22108eaa18e1a079144738e3c7737c 
### Minor changes as xPath was broken
def scrape_pfsense_dhcp(url, user, password):
    ip = []
    mac = []
    dhcp_name = []
    description = []

    s = requests.session()
    r = s.get(url,verify = False)

    matchme = 'csrfMagicToken = "(.*)";var'
    csrf = re.search(matchme,str(r.text))

    payload =   {
                    '__csrf_magic' : csrf.group(1),
                    'login' : 'Login',
                    'usernamefld' : user,
                    'passwordfld' : password
                }
    r = s.post(url,data=payload,verify = False)
    r = s.get(url,verify = False)
    tree = html.fromstring(r.content)

    tr_elements = tree.xpath('//tr')
    headers = [header.text for header in tr_elements[0]]
    
    #ip.extend(tree.xpath('//body[1]//div[1]//div[2]//div[2]//table[1]//tbody//tr//td[' + str(headers.index('IP address') + 1) +']//text()'))
    #mac.extend(tree.xpath('//body[1]//div[1]//div[2]//div[2]//table[1]//tbody//tr//td['+ str(headers.index('MAC address') + 1) +']//text()'))
    #description.extend(tree.xpath('//body[1]//div[1]//div[2]//div[2]//table[1]//tbody//tr//td['+ str(headers.index('Description') + 1) +']//text()'))
    ip.extend(tree.xpath('/html/body/div[1]/div[3]/div[2]/table/tbody/tr/td[' + str(headers.index('IP address') + 1) +']//text()'))
    mac.extend(tree.xpath('/html/body/div[1]/div[3]/div[2]/table/tbody/tr/td[' + str(headers.index('MAC address') + 1) +']//text()'))
    description.extend(tree.xpath('/html/body/div[1]/div[3]/div[2]/table/tbody/tr/td[' + str(headers.index('Description') + 1) +']//text()'))
    
    for node in tree.xpath('/html/body/div[1]/div[3]/div[2]/table/tbody/tr/td['+ str(headers.index('Hostname') + 1) +']'):
        if node.text is None:
              dhcp_name.append('no_hostname')
        else:
              dhcp_name.append(node.text)
    for i in range(len(mac)):
          mac[i] = mac[i].strip()
    for i in range(len(description)):
          description[i] = description[i].strip()
    return(list(zip(ip, mac, dhcp_name, description)))

### This funtion adapted from code here: https://gist.github.com/haukurk/5ef80fa47ee60e815ce7
def send_syslog(message, level=LEVEL['notice'], facility=FACILITY['daemon'],
    host=str(firewall_ip), port=firewall_port):
    """
    Send syslog UDP packet to given host and port.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = '<%d>%s' % (level + facility*8, message)
    data2 = bytes(data,'utf-8')
    sock.sendto(data2, (host, port))
    sock.close()

### Run's forever. Recommended to Daemonize or run within 'screen' (or other console app) in dedicated system
while True:
    result = scrape_pfsense_dhcp(url, user, password)
    for item in result:
        #Format of Syslog Message 
        #  auth: username myuser ip 1.2.3.4
        # Message is derived from PFsense IP (item[0]) and PFsense DHCP Lease Description (item[3])
        message = "auth: username " + str(item[3]).lower() + " ip " + str(item[0]).lower()
        send_syslog(message=message,level=LEVEL['notice'], facility=FACILITY['daemon'],host=firewall_ip, port=firewall_port)
        print(message)
        time.sleep(per_message_delay_timer)
    time.sleep(cycle_timer)

