from scapy.all import *
import datetime
from mitigation import checkValidity




conf.sniff_promisc=True
pcap_specified = False
map1 = defaultdict(list)

hostname_map = {"imdb.com", "stonybrook.edu", "blackboard.com","whatsapp.com", "office.com","netflix.com","spotify.com","myshopify.com","wikipedia.org"}

def parse(s):
    index = -1
    index2 =-1
    for i in range(0,len(s)):
        if s[i] == '.' and i!=len(s)-2:
            index2 = index
            index=i
    return index2



def detect_poison2(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if pkt.haslayer(DNSRR) and  len(pkt[Ether]) > 60 and len(pkt[UDP]) > 8:
            key = str(pkt[DNS].id) + str(pkt[DNS].qd.qname) + str(pkt[IP].sport) + ">" + str(pkt[IP].dst) + ":" + str(pkt[IP].dport)
            
            list_a1=[]
            for i in range(pkt[DNS].ancount):
                dnsrr = pkt[DNS].an[i]
                if isinstance(dnsrr.rdata,str):
                    list_a1.append(str(dnsrr.rdata))
            
            if list_a1 is not None and len(list_a1)>0:
                strng = str(pkt[DNS].qd.qname)
                query1 = strng[parse(strng)+1:len(strng)-2]
                ip_add = list_a1[0]
                query_name = str(pkt[DNS].qd.qname)[str(pkt[DNS].qd.qname).index('.')+1:len(str(pkt[DNS].qd.qname))-2]
                if query1 in hostname_map:
                    print(str(pkt[DNS].qd.qname)[2:],ip_add)
                    response = checkValidity(query_name,ip_add)
                    
                    if response:
                        print("Non poisoned IP")
                    else:
                        print("Poisoned IP")

capture = sniff(iface = "enp0s3" , filter = "udp port 53",prn = detect_poison2, store =0)
capture.summary()