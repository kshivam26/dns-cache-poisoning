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

print(checkValidity("bankofamerica.com", '171.159.228.150'))
print ('validity for facebook')
print(checkValidity("facebook.com", '157.240.229.35'))
print ('validity for google')
print(checkValidity("google.com", '172.217.15.110'))
