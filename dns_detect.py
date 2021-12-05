

from scapy.all import *
import datetime
from poisoining_mitigator import checkValidity




conf.sniff_promisc=True
pcap_specified = False
map1 = defaultdict(list)

hostname_map = {"imdb.com", "stonybrook.edu", "blackboard.com","whatsapp.com", "office.com","netflix.com","spotify.com","myshopify.com","wikipedia.org"}



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
                
                if len(map1[key])>2:
                    print(map1[key][2:])
                else:
                    print(map1[key][1])

                print("Answer 2")
                list_a1=[]
                for i in range(pkt[DNS].ancount):
                    dnsrr = pkt[DNS].an[i]
                    if isinstance(dnsrr.rdata,str):
                        list_a1.append(str(dnsrr.rdata))
                
                print(list_a1)
            
            else:
                map1[key] = [str(pkt[IP].payload), "Non A type Response"]
                for i in range(pkt[DNS].ancount):
                    dnsrr = pkt[DNS].an[i]
                    if isinstance(dnsrr.rdata,str):
                        map1[key].append(str(dnsrr.rdata))
                        
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
                query_name = str(pkt[DNS].qd.qname)[str(pkt[DNS].qd.qname).index('.')+1:len(str(pkt[DNS].qd.qname))-2]
                ip_add = list_a1[0]
                if query_name in hostname_map:
                    print(pkt[DNS].qd.qname)
                    print(query_name,ip_add)
                    response = checkValidity(query_name,ip_add)
                    
                    if response:
                        print("Non poisoned IP")
                    else:
                        print("Poisoned IP")
                else:
                    print("Pass")

capture = sniff(iface = "en0" , filter = "udp port 53",prn = detect_poison2, store =0)
capture.summary()

