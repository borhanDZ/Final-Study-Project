# coding: utf-8
from scapy.all import IP,UDP,DHCP,BOOTP,sniff
from time import *
import Net_Info as local_Net

def interfaceDhcp():
   print """\033[1;32;48m 
DDDDDDDDDDDDD             HHHHHHHHH     HHHHHHHHH             CCCCCCCCCCCCC     PPPPPPPPPPPPPPPPP                    DDDDDDDDDDDDD        
D::::::::::::DDD          H:::::::H     H:::::::H          CCC::::::::::::C     P::::::::::::::::P                   D::::::::::::DDD     
D:::::::::::::::DD        H:::::::H     H:::::::H        CC:::::::::::::::C     P::::::PPPPPP:::::P                  D:::::::::::::::DD   
DDD:::::DDDDD:::::D       HH::::::H     H::::::HH       C:::::CCCCCCCC::::C     PP:::::P     P:::::P                 DDD:::::DDDDD:::::D  
  D:::::D    D:::::D        H:::::H     H:::::H        C:::::C       CCCCCC       P::::P     P:::::P                   D:::::D    D:::::D 
  D:::::D     D:::::D       H:::::H     H:::::H       C:::::C                     P::::P     P:::::P                   D:::::D     D:::::D
  D:::::D     D:::::D       H::::::HHHHH::::::H       C:::::C                     P::::PPPPPP:::::P                    D:::::D     D:::::D
  D:::::D     D:::::D       H:::::::::::::::::H       C:::::C                     P:::::::::::::PP   ---------------   D:::::D     D:::::D
  D:::::D     D:::::D       H:::::::::::::::::H       C:::::C                     P::::PPPPPPPPP     -:::::::::::::-   D:::::D     D:::::D
  D:::::D     D:::::D       H::::::HHHHH::::::H       C:::::C                     P::::P             ---------------   D:::::D     D:::::D
  D:::::D     D:::::D       H:::::H     H:::::H       C:::::C                     P::::P                               D:::::D     D:::::D
  D:::::D    D:::::D        H:::::H     H:::::H        C:::::C       CCCCCC       P::::P                               D:::::D    D:::::D 
DDD:::::DDDDD:::::D       HH::::::H     H::::::HH       C:::::CCCCCCCC::::C     PP::::::PP                           DDD:::::DDDDD:::::D  
D:::::::::::::::DD        H:::::::H     H:::::::H        CC:::::::::::::::C     P::::::::P                           D:::::::::::::::DD   
D::::::::::::DDD          H:::::::H     H:::::::H          CCC::::::::::::C     P::::::::P                           D::::::::::::DDD     
DDDDDDDDDDDDD             HHHHHHHHH     HHHHHHHHH             CCCCCCCCCCCCC     PPPPPPPPPP                           DDDDDDDDDDDDD  \n"""


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

list_time = [0]
list_dhcp = []
op = [1,2,3,5]

random_mac = ["47:58:97:70:70:40","96:EE:70:E4:75:A9","0D:CA:4B:FC:F5:DE","F6:C8:41:02:41:87","76:D2:67:30:7B:02","0B:F8:2D:84:54:35","2B:6E:86:40:DD:C6","FA:B0:BA:35:E5:FD","C8:5C:27:DE:8E:42","4D:21:80:5D:5A:4F","88:81:53:1D:43:9D"]

#########************ call Functions *************#########

def dhcp_scan(list_dhcp):

    list_dhcp.append(1)
    if len(list_dhcp) >= 100:
        return True
    else:
        return False


# this function check differnt period between packet dhcp whose captured !!important function in real Time
def time_check(list_time):
   if len(list_time)> 100 :
      moment1 = list_time[len(list_time) - 20]
      moment2 = list_time[len(list_time) - 1]
      time = moment2 - moment1  # epoch time
      if time <= 0.002:
        return True
      else:
        return False


# this function update list_dhcp (set vide) every 30 second
def update_list_packet():
    # https://www.programiz.com toturial python time module
    named_tuple = localtime()  # get struct_time
    time_string = strftime("%S", named_tuple)
    # time_string = time.strftime("%m/%d/%Y, %H:%M:%S", named_tuple)
    if time_string == '30' or time_string == '00':
        if list_dhcp != []:
           for i in range(len(list_dhcp)):
               list_dhcp.pop()
######"""""""" run automatic in moment when connect on local network for initial check DHCP server :Host mode""""""""""""""
def check_dhcp_host():
    #Gateway = local_Net.get_default_gateway_linux()
    #######*********** mode host *********
    print "DHCP Detect in HOST mode: We are still working on it due to some small problems"



######*********** main function: handle_DHCP handle DHCP packet :Network mode*************
def handle_dhcp_packet(packet):
    """ parse dns request / response packet """
    if DHCP in packet and packet.getlayer(DHCP).fields['options'][0][1] in op:
        if packet[DHCP].options[0][1] == 1:
            option = 'New DHCP Discover'
        elif packet[DHCP].options[0][1] == 2:
            option = 'New DHCP Offer'
        elif packet[DHCP].options[0][1] == 3:
            option = 'New DHCP Request'
        elif packet[DHCP].options[0][1] == 5:
            option = 'New DHCP Ack'
        hwr = packet['BOOTP'].chaddr
        T = time()
        list_time.append(T)
        update_list_packet()
        if dhcp_scan(list_dhcp) and time_check(list_time):
           print "\033[1;31;40m[*]warning:\033[0m spoofed DHCP process %o: %h"%(op,hwr)

        #print(packet.summary())
        #print(ls(packet))


