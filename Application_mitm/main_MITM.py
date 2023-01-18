# !/usr/bin/env python
# coding: utf-8
from ARP_Detect import scarpwatch_ARP,interfaceArp
from DNS_Detect import handle_dns,interfaceDns
from DHCP_Detect import handle_dhcp_packet,check_dhcp_host,interfaceDhcp
from Style import InterStyle,style_list

import argparse
from scapy.all import sniff


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-A", dest="arp" , help="execute a 'ARP Detect' for detect ARP spoofing attack")
    parser.add_argument("-D", dest="dns" , help="execute a 'DNS Detect' for detect DNS spoofing attack")
    parser.add_argument("-DN", dest="dhcp", help="if you already inside right Network execute a 'DHCP Detect' for detect DHCP spoofing attack")
    parser.add_argument("-DH", dest="dhcphost", help="execute a 'DHCP Detect' for detect DHCP spoofing attack from initial check DHCP server :Host mode")
    parser.add_argument("-l", help="Listen connections from any IP address")
    return parser.parse_args()

def DetectAll(pkt):
    # execute all main file ARP,DNS,DHCP
    scarpwatch_ARP(pkt)
    handle_dns(pkt)
    handle_dhcp_packet(pkt)

#adapt argument what you want to execute
def execute(args):
    if args.arp or args.dns or args.dhcp:
        return True
    else: return False

#*********** main program function ***********
def main():

    args = argument()
    arp = args.arp
    dns = args.dns
    dhcp= args.dhcp
    dhcpHost= args.dhcphost

    if not execute(args):
       InterStyle(style_list)
       print "\n";check_dhcp_host()
       try:
           sniff(store=0, prn=DetectAll)
       except :
           print "\033[1;31;48m[!] \033[0msniff Function is not exist!"
           print "please check already you have been installed scapy 2.4.0"
    else:
       if arp:
           interfaceArp()
           try:
               sniff(prn=scarpwatch_ARP, filter='arp' ,store=0)
           except:
               print "\033[1;31;48m[!] \033[0msniff Function is not exist!"
               print "please check already you have been installed scapy 2.4.0"
       if dns:
           interfaceDns()
           try:
               sniff(filter="udp port 53", prn=handle_dns ,store=0)
           except:
               print "\033[1;31;48m[!] \033[0msniff Function is not exist!"
               print "please check already you have been installed scapy 2.4.0"
       if dhcp:
           interfaceDhcp()
           try:
               sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp_packet ,store=0)
           except:
               print "\033[1;31;48m[!] \033[0msniff Function is not exist!"
               print "please check already you have been installed scapy 2.4.0"
       if dhcpHost:
           interfaceDhcp()
           try:
               sniff(filter="udp and (port 67 or 68)", prn=check_dhcp_host ,store=0)
           except:
               print "\033[1;31;48m[!] \033[0msniff Function is not exist!"
               print "please check already you have been installed scapy 2.4.0"




if __name__ == '__main__':

  try:
      main()
  except KeyboardInterrupt:
      pass
