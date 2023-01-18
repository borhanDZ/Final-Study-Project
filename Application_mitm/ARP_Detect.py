# !/usr/bin/env python
# coding: utf-8
from scapy.layers.l2 import ARP, Ether
from time import *
import datetime as date
import Net_Info as local_Net

def interfaceArp():

   print """\033[1;32;48m
               AAA                    RRRRRRRRRRRRRRRRR        PPPPPPPPPPPPPPPPP                    DDDDDDDDDDDDD
              A:::A                   R::::::::::::::::R       P::::::::::::::::P                   D::::::::::::DDD     
             A:::::A                  R::::::RRRRRR:::::R      P::::::PPPPPP:::::P                  D:::::::::::::::DD   
            A:::::::A                 RR:::::R     R:::::R     PP:::::P     P:::::P                 DDD:::::DDDDD:::::D  
           A:::::::::A                  R::::R     R:::::R       P::::P     P:::::P                   D:::::D    D:::::D 
          A:::::A:::::A                 R::::R     R:::::R       P::::P     P:::::P                   D:::::D     D:::::D
         A:::::A A:::::A                R::::RRRRRR:::::R        P::::PPPPPP:::::P                    D:::::D     D:::::D
        A:::::A   A:::::A               R:::::::::::::RR         P:::::::::::::PP   ---------------   D:::::D     D:::::D
       A:::::A     A:::::A              R::::RRRRRR:::::R        P::::PPPPPPPPP     -:::::::::::::-   D:::::D     D:::::D
      A:::::AAAAAAAAA:::::A             R::::R     R:::::R       P::::P             ---------------   D:::::D     D:::::D
     A:::::::::::::::::::::A            R::::R     R:::::R       P::::P                               D:::::D     D:::::D
    A:::::AAAAAAAAAAAAA:::::A           R::::R     R:::::R       P::::P                               D:::::D    D:::::D 
   A:::::A             A:::::A        RR:::::R     R:::::R     PP::::::PP                           DDD:::::DDDDD:::::D  
  A:::::A               A:::::A       R::::::R     R:::::R     P::::::::P                           D:::::::::::::::DD   
 A:::::A                 A:::::A      R::::::R     R:::::R     P::::::::P                           D::::::::::::DDD     
AAAAAAA                   AAAAAAA     RRRRRRRR     RRRRRRR     PPPPPPPPPP                           DDDDDDDDDDDDD    \n"""

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

# Declaration variable
DB = {}
list_time = [0]
list_arp = []
ok = []
j = 0

# this function check inside list it fill or no of ARP packets Type reply
def ARP_scan(pkt, list_arp):
    if pkt[ARP].op == 1:
        list_arp.append(1)
    if len(list_arp) >= 700:
        return True
    else:
        return False


# this function check differnt period between packet ARP whose captured !!important function in real Time
def time_check(list_time):
    moment1 = list_time[len(list_time) - 2]
    moment2 = list_time[len(list_time) - 1]
    time = moment2 - moment1  # epoch time
    if time <= 0.001:
        return True
    else:
        return False


# this function update list_arp (set vide) every 30 second
def update_list_packet():
    # https://www.programiz.com toturial python time module
    named_tuple = localtime()  # get struct_time
    time_string = strftime("%S", named_tuple)
    # time_string = time.strftime("%m/%d/%Y, %H:%M:%S", named_tuple)
    #print  time_string
    if time_string == '30' or time_string == '00':
        if list_arp != []:
           for i in range(len(list_arp)):
               list_arp.pop()

# this Function get result the attacker that he obtain it
def attack_result(pkt, ok):
    global j
    count = int(real_time())
    count = count - int(j)
    if ok != [] and pkt[ARP].op == 2:
        if count >= 7 or count <= 0:
            ok.pop()
            return
        print "\033[1;32;40m [!] \033[0m", pkt[
            ARP].psrc, " \033[1;33;40m ---------> \033[0m", "\033[1;31;40m [!]attcker \033[0m", pkt[ARP].pdst, "\n"


# This Function get real Time of second a moment we needed
def real_time():
    lt = localtime()
    get_time = strftime("%S", lt)
    return get_time

######*********** main function: scarpwatch_ARP handle ARP packet  *************

def scarpwatch_ARP(pkt):
    global j  # global varible we use for stock the currently moment

    if ARP in pkt:

        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
        T = time()
        list_time.append(T)
        update_list_packet()

        if ARP_scan(pkt, list_arp) and time_check(list_time):
            print """\033[1;31;40m  [!]warning:\033[0m An attack occurs on the network. Someone checks for the presence of machines 
             in the network and this is the result of the survey see below\n"""
            print strftime(" incident date %m/%d/%Y::%H:%M:%S", localtime())
            j = real_time()
            ok.append("good")  # ok it is list varible we use to check among thousands of arp packets in function attack_result() for get exactly result of arp reply that attcker want it
            sleep(1)
            for bit in range(len(list_time) - 1):  # vide now list time
                list_time.pop()
            for bit in range(len(list_arp) - 1):  # vide now list ARP_packet
                list_arp.pop()
        attack_result(pkt, ok)
        if ip in DB:
            if mac != DB[ip]:
                if Ether in pkt:
                    target = pkt[ARP].pdst
                else:
                    target = pkt[ARP].pdst
                if ip == local_Net.get_default_gateway_linux():
                    print "\033[1;31;40m [*]warning:\033[0m ARP poisoning attack: \033[1;32;40mtarget=\033[0m%s \033[1;33;40mGatway=  \033[0m%s \033[1;31;40mattacker=\033[0m%s" % (
                    target, ip, mac)
                elif ip == local_Net.get_ip_linux():
                    print "\033[1;31;40m [*]warning:you'r target\033[0m ARP poisoning attack: \033[1;33;40mGatway=\033[0m%s \033[1;32;40mtarget=\033[0m%s \033[1;31;40mattacker=\033[0m%s" % (
                    target, ip, mac)
                else:
                    print "\033[1;31;40m [*]warning:\033[0m ARP poisoning attack: \033[1;33;40mGatway=\033[0m%s \033[1;32;40mtarget=\033[0m%s \033[1;31;40mattacker=\033[0m%s" % (
                    target, ip, mac)
        else:
            DB[ip] = mac
