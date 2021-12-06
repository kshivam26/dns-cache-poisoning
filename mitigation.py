from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime
import idna
from OpenSSL import SSL
from socket import socket
import time
from timeout import timeout

def get_certificate(ip_address, port):
    try:
        sock = socket()
        # sock.settimeout(100)
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
    except BaseException as e:
        #print(e.__class__)
        #print('exception occured')
        return None

def get_alternate_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        #print("except")
        return None

def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(names) > 0:
            return names[0].value
        else:
            return None
    except x509.ExtensionNotFound:
        #print("except")
        return None

@timeout(3)
def checkValidity(host_name, ip_address):
    cert = get_certificate(ip_address, 443)
    now = datetime.utcnow()
    # print (cert)
        
    if not cert:
        #print ('certificate not found')
        return False

    if (get_common_name(cert) and not get_common_name(cert).endswith(host_name)):     # Check if common name ends with host name
        valid = False   
        for val in get_alternate_names(cert):               # Check if any alternate name ends with host name
            if val.endswith(host_name):
                valid = True
                break
        if not valid:
            #print('hostname is not valid')
            return False
    if now < cert.not_valid_before:
        #print('not_valid_before is not valid')
        return False
    if now > cert.not_valid_after:
        #print('not_valid_after is not valid')
        return False
    return True
'''
print ('validity for oyo.om')
print(checkValidity("oyo.com", '10.0.0.1'))
print ('validity for imdb.com')
print(checkValidity("imdb.com", '10.0.0.2'))
print ('validity for stonybrook.edu')
print(checkValidity("stonybrook.edu", '10.0.0.3'))
print ('validity for blackboard')
print(checkValidity("blackboard.com", '10.0.0.4'))
print ('validity for whatsapp.com')
print(checkValidity("whatsapp.com", '10.0.0.5'))
print ('validity for netflix.com')
print(checkValidity("netflix.com", '10.0.0.6'))
print ('validity for spotify.com')
print(checkValidity("spotify.com", '10.0.0.7'))
print ('validity for myshofify')
print(checkValidity("myshopify.com","10.0.0.8"))
print ('validity for  wikipedia')
print(checkValidity("wikipedia.org","10.0.0.9"))
'''