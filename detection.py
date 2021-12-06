from scapy.all import *

conf.sniff_promisc=True
pcap_specified = False
map1 = defaultdict(list)

hostname_map = {"www.imdb.com", "www.stonybrook.edu", "www.blackboard.com","www.whatsapp.com", "www.office.com","www.netflix.com","www.spotify.com","www.myshopify.com","www.wikipedia.org"}

def detect_poison(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if pkt.haslayer(DNSRR) and  len(pkt[Ether]) > 60 and len(pkt[UDP]) > 8:
            key = str(pkt[DNS].id) + str(pkt[DNS].qd.qname) + str(pkt[IP].sport) + ">" + str(pkt[IP].dst) + ":" + str(pkt[IP].dport)
            if key in map1 and str(pkt[IP].payload) != map1[key][0]:
                print("TXID 0x",str(pkt[DNS].id), "Request", str(pkt[DNS].qd.qname))
                print("Poisioning attempt")
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
                        


capture = sniff(iface = "enp0s3" , filter = "udp port 53",prn = detect_poison, store =0)
capture.summary()