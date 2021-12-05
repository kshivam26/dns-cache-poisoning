#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Dec  4 15:47:43 2021

@author: admin_sikandar
"""

from scapy.all import *
import datetime

conf.sniff_promisc=True
pcap_specified = False
map1 = defaultdict(list)

def pkt1(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if pkt.haslayer(DNSRR) and  len(pkt[Ether]) > 60 and len(pkt[UDP]) > 8:
            key = str(pkt[DNS].id) + str(pkt[DNS].qd.qname) + str(pkt[IP].sport) + ">" + str(pkt[IP].dst) + ":" + str(pkt[IP].dport)
            print(key)
            
    else:
        print("fuckup")
    


def detect_poison(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if pkt.haslayer(DNSRR) and  len(pkt[Ether]) > 60 and len(pkt[UDP]) > 8:
            key = str(pkt[DNS].id) + str(pkt[DNS].qd.qname) + str(pkt[IP].sport) + ">" + str(pkt[IP].dst) + ":" + str(pkt[IP].dport)
            if key in map1 and str(pkt[IP].payload) != map1[key][0]:
                date = datetime.datetime.fromtimestamp(pkt.time)
                print("DNS Poisioning attempt")
                print("TXID 0x",str(pkt[DNS].id), "Request", str(pkt[DNS].qd.qname))
                print("Answer 1")
                list_a1=[]
                for i in range(pkt[DNS].ancount):
                    dnsrr = pkt[DNS].an[i]
                    list_a1.append(dnsrr.rdata)
                
                print(list_a1)
                
                print("Answer 2")
                
                if len(map1[key])>2:
                    print(map1[key][2:])
                else:
                    print(map1[key][1])
            
            else:
                map1[key] = [str(pkt[IP].payload), "Non A type Response"]
                for i in range(pkt[DNS].ancount):
                    dnsrr = pkt[DNS].an[i]
                    map1[key].append(str(dnsrr.rdata))
                



capture = sniff(iface = "enp0s3" , filter = "udp port 53",prn = detect_poison, store =0)
capture.summary()

