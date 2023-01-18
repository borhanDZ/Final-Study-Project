#!/usr/bin/env python
# -*- coding: utf8 -*-

"""DNS """

from scapy.all import*
from time import sleep

# disable verbose mode
conf.verb = 0

def interfaceDns():
   print """\033[1;32;48m 
DDDDDDDDDDDDD             NNNNNNNN        NNNNNNNN        SSSSSSSSSSSSSSS                  DDDDDDDDDDDDD        
D::::::::::::DDD          N:::::::N       N::::::N      SS:::::::::::::::S                 D::::::::::::DDD     
D:::::::::::::::DD        N::::::::N      N::::::N     S:::::SSSSSS::::::S                 D:::::::::::::::DD   
DDD:::::DDDDD:::::D       N:::::::::N     N::::::N     S:::::S     SSSSSSS                 DDD:::::DDDDD:::::D  
  D:::::D    D:::::D      N::::::::::N    N::::::N     S:::::S                               D:::::D    D:::::D 
  D:::::D     D:::::D     N:::::::::::N   N::::::N     S:::::S                               D:::::D     D:::::D
  D:::::D     D:::::D     N:::::::N::::N  N::::::N      S::::SSSS                            D:::::D     D:::::D
  D:::::D     D:::::D     N::::::N N::::N N::::::N       SS::::::SSSSS     ---------------   D:::::D     D:::::D
  D:::::D     D:::::D     N::::::N  N::::N:::::::N         SSS::::::::SS   -:::::::::::::-   D:::::D     D:::::D
  D:::::D     D:::::D     N::::::N   N:::::::::::N            SSSSSS::::S  ---------------   D:::::D     D:::::D
  D:::::D     D:::::D     N::::::N    N::::::::::N                 S:::::S                   D:::::D     D:::::D
  D:::::D    D:::::D      N::::::N     N:::::::::N                 S:::::S                   D:::::D    D:::::D 
DDD:::::DDDDD:::::D       N::::::N      N::::::::N     SSSSSSS     S:::::S                 DDD:::::DDDDD:::::D  
D:::::::::::::::DD        N::::::N       N:::::::N     S::::::SSSSSS:::::S                 D:::::::::::::::DD   
D::::::::::::DDD          N::::::N        N::::::N     S:::::::::::::::SS                  D::::::::::::DDD     
DDDDDDDDDDDDD             NNNNNNNN         NNNNNNN      SSSSSSSSSSSSSSS                    DDDDDDDDDDDDD    \n"""


   sleep(1.5)
   print """\033[1;36;48m this a little tool has been made in Graduation Project Master 2
     version = 0.1"""
   sleep(0.5)
   print "\033[1;36;48m email: borhan14041995@yahoo.com "
   sleep(0.5)
   print "\033[1;32;48m start: ",
   l = ["*"]
   for i in range(1, 30):
      if i == 1 or i == 29:
         print "//",
      else:
         print l[0],
      sleep(0.1)
   sleep(1.5)
   print "\033[0m\n"
   print "\033[1;32;40m>> Don't write any thing\033[0m\n  "

#declartion variable
inspect_domain = []
inspect_qname_id = []

#inspect_pkt_DNS_for_AllDomain_spoofed
def inspect_pkt(ip,udp,inspect_domain):
            count = 0
            succes = False
            if len(inspect_domain)>= 40:
                for i in range(len(inspect_domain)):
                    dns_stuk = inspect_domain[i]
                    if i < 10:
                        for j in range(len(inspect_domain)):
                           if i != j:
                              otherDns = inspect_domain[j]
                              if (dns_stuk.an.rdata == otherDns.an.rdata):
                                    count+=1
                                    if count == 10:
                                      succes = True
                                      print "\033[1;31;40m[*]warning:\033[0m spoofed DNS response %s:%d <--- %s:%d domain=%s"%(ip.src, udp.sport, ip.dst, udp.dport, dns_stuk.an.rrname)
                                      print "\033[1;31;48mAll domains spoofed\n"
            return succes
#inspect_pkt_for_one_Domain_spoofed
def inspect_dns_ID(inspect_qname_id,ip,udp,check):
    test = False
    print "**********",len(inspect_qname_id),type(check),check
    if len(inspect_qname_id) >=30 and not check:
        for i in range(len(inspect_qname_id)):
            dns_id = inspect_qname_id[i]
            for j in range(len(inspect_qname_id)):
                if i!=j:
                   otherID = inspect_qname_id[j]

                   if dns_id.id == otherID.id and dns_id.an.rrname == otherID.an.rrname:
                         test = True
                         print "\033[1;31;40m[*]warning:\033[0m spoofed response %s:%d <--- %s:%d domain=%s id: %d"%(
                         ip.src, udp.sport, ip.dst, udp.dport, dns_id.an.rrname,dns_id.id)
                         print "\033[1;36;48m spoofed for one domain=\033[0m%s"%(dns_id.an.rrname),"\n"
        return test


def vide(check,test,l1,l2):
    if check :
        for i in range(len(l1)):
            l1.pop()
    elif test:
        for i in range(len(l2)):
            l2.pop()


######*********** main function: handle_DNS handle DNS packet  *************
def handle_dns(pkt):
    """ parse dns request / response packet """
    if pkt.haslayer('UDP') and pkt.haslayer('DNS'):
        ip  = pkt['IP']
        udp = pkt['UDP']
        dns = pkt['DNS']

        if dns.qr == 1 and dns.ancount == 1 and dns.an.type == 1:
           inspect_domain.append(dns)
           inspect_qname_id.append(dns)
           check = inspect_pkt(ip,udp,inspect_domain)
           #test  = inspect_dns_ID(inspect_qname_id,ip,udp,check)
           test = False
           vide(check,test,inspect_domain,inspect_qname_id)

"""
        # dns query packet
        if int(udp.dport) == 53:
            qname = dns.qd.qname

           # print "\n\033[1;36;48m [*][DNS]request: %s:%d -> %s:%d : domain=%s id: %d" % (
                ip.src, udp.sport, ip.dst, udp.dport, qname,dns.id),"type: "

        # dns reply packet

        elif int(udp.sport) == 53:
            # dns DNSRR count (answer count)

             for i in range(dns.ancount):
                dnsrr = dns.an[i]
                if dns.an.type == 1:
                    print "\033[1;32;48m[*][DNS]response: %s:%s <- %s:%d :%s - %s id: %d" % (
                    ip.dst, udp.dport,
                    ip.src, udp.sport,
                    dnsrr.rrname, dnsrr.rdata,dns.id)"""

