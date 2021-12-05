from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime
import idna
from OpenSSL import SSL
from socket import socket

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
        print(e.__class__)
        print('exception occured')
        return None

def get_alternate_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None

def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(names) > 0:
            return names[0].value
        else:
            return None
    except x509.ExtensionNotFound:
        return None

def checkValidity(host_name, ip_address):
    cert = get_certificate(ip_address, 443)
    now = datetime.utcnow()
    # print (cert)
    # print('common names')
    # print(get_common_name(cert))
    # print('alternate names')
    # print(get_alternate_names(cert))
    if not cert:
        print ('certificate not found')
        return False

    if (get_common_name(cert) and not get_common_name(cert).endswith(host_name)):     # Check if common name ends with host name
        valid = False   
        for val in get_alternate_names(cert):               # Check if any alternate name ends with host name
            if val.endswith(host_name):
                valid = True
                break
        if not valid:
            print('hostname is not valid')
            return False
    if now < cert.not_valid_before:
        print('not_valid_before is not valid')
        return False
    if now > cert.not_valid_after:
        print('not_valid_after is not valid')
        return False
    return True

# print ('validity for bank of america')
# print(checkValidity("bankofamerica.com", '10.0.0.1'))
# print ('validity for facebook')
# print(checkValidity("facebook.com", '157.240.229.35'))
# print ('validity for google')
# print(checkValidity("google.com", '172.217.15.110'))
# print ('validity for apple')
# print(checkValidity("apple.com", '23.220.132.219'))
# print ('validity for netflix.com')
# print(checkValidity("netflix.com", '54.237.226.164'))
# print ('validity for googleapis.com')
# print(checkValidity("googleapis.com", '172.217.1.202'))
# print ('validity for amazonaws.com')
# print(checkValidity("amazonaws.com", '52.217.81.80'))
# print ('validity for Amazon')
# print(checkValidity("amazon.com","54.239.17.248"))

# print ('validity for  python.org')
# print(checkValidity("python.org","138.197.63.241"))
print ('validity for BOFA')
print(checkValidity("bankofamerica.com","54.163.234.74"))