#!/usr/bin/env python
import os
import socket
import struct
import subprocess

def get_ip_linux():
    file=os.popen("ifconfig | grep 'inet '")
    data=file.read()
    file.close()
   # print(data)
    bits=data.strip().split('\n')
    #print bits
    for bit in bits:
        if bit.strip().startswith("inet "):
            other_bits=bit.strip().split(' ')
            for obit in other_bits:
                #print obit,"\n"
                if (obit.count('.')==3):
                    if not obit.startswith("127."):
                        ip = obit
                    break
    return ip
#print get_ip_linux()

def get_default_gateway_linux():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue
            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

#print get_default_gateway_linux()

def system_call(command):
    p = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True)
    return p.stdout.read()

def get_arp_table():
    return system_call("arp -a")
#print get_arp_table()
