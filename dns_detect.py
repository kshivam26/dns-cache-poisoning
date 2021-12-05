

from scapy.all import *
import datetime
import poisoining_mitigator


from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime
import idna
from OpenSSL import SSL
from socket import socket

def get_certificate(ip_address, port):
    sock = socket()
    sock.connect((ip_address, port))
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(idna.encode(ip_address))
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()    
    sock_ssl.close()
    sock.close()
    return cert.to_cryptography()

def get_alternate_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None

def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def checkValidity(host_name, ip_address):
    cert = get_certificate(ip_address, 443)
    now = datetime.now()
    if host_name != get_common_name(cert) and host_name not in get_alternate_names(cert):
        print('hostname is not valid')
        return False
    if now < cert.not_valid_before:
        print('not_valid_before is not valid')
        return False
    if now > cert.not_valid_after:
        print('not_valid_after is not valid')
        return False
    return True

conf.sniff_promisc=True
pcap_specified = False
map1 = defaultdict(list)



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
                print(str(pkt[DNS].qd.qname)[str(pkt[DNS].qd.qname).index('.')+1:len(str(pkt[DNS].qd.qname))-2],list_a1[0])
                
                '''
                print(str(pkt[DNS].qd.qname))
                print(str(pkt[DNS].qd.qname)[str(pkt[DNS].qd.qname).index('.')+1:len(str(pkt[DNS].qd.qname))-2])
                
                if checkValidity(str(pkt[DNS].qd.qname)[str(pkt[DNS].qd.qname).index('.')+1:len(str(pkt[DNS].qd.qname))-2], list_a1[0]):
                    print("Non poisioned IP")
                else:
                    print("Poisoned IP")
                '''
                    

            else:
                print("Pass")
                



capture = sniff(iface = "en0" , filter = "udp port 53",prn = detect_poison2, store =0)
capture.summary()

