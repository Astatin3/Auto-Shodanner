import random
import datetime
import socket
import ssl
import OpenSSL

from faker import Faker


def generate_headers():
  fake = Faker()
  return "\r\n".join([
    f"User-Agent: {fake.user_agent()}",
    f"Accept: {fake.mime_type()}",
    f"Accept-Language: {fake.language_code()},{fake.language_code()};q=0.9",
    f"Accept-Encoding: {fake.mime_type()}, {fake.mime_type()}, {fake.mime_type()}",
    f"Referer: {fake.url()}",
    f"Connection: {random.choice(['keep-alive', 'close'])}",
    f"Cache-Control: {random.choice(['no-cache', 'max-age=0'])}",
    f"Pragma: {random.choice(['no-cache', ''])}",
  ]) + "\r\n\r\n"



def get_ssl_cert_info(cert_data):
  if not cert_data:
    return ""
  
  cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_data)
  
  string = "Certificate Information:\n"
  string += "------------------------\n"

  string += "Subject:\n"
  subject = cert.get_subject()
  string += f"  Common Name (CN): {subject.CN}\n"
  string += f"  Organization (O): {subject.O}\n"
  string += f"  Organizational Unit (OU): {subject.OU}\n"
  string += f"  Country (C): {subject.C}\n"
  string += f"  State/Province (ST): {subject.ST}\n"
  string += f"  Locality (L): {subject.L}\n"

  string += "\nIssuer:\n"
  issuer = cert.get_issuer()
  string += f"  Common Name (CN): {issuer.CN}\n"
  string += f"  Organization (O): {issuer.O}\n"
  string += f"  Organizational Unit (OU): {issuer.OU}\n"
  string += f"  Country (C): {issuer.C}\n"
  string += f"  State/Province (ST): {issuer.ST}\n"
  string += f"  Locality (L): {issuer.L}\n"

  string += f"\nVersion: {cert.get_version() + 1}"
  string += f"Serial Number: {cert.get_serial_number()}"
  
  not_before = datetime.datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
  not_after = datetime.datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
  string += f"Not Before: {not_before}\n"
  string += f"Not After: {not_after}\n"

  string += f"Expired: {cert.has_expired()}\n"

  string += "\nExtensions:\n"
  for i in range(cert.get_extension_count()):
      ext = cert.get_extension(i)
      string += f"  {ext.get_short_name().decode('utf-8')}: {ext}\n"

  string += "\nSignature Algorithm:\n"
  string += f"  {cert.get_signature_algorithm().decode('utf-8')}\n"

  string += "\nPublic Key:\n"
  public_key = cert.get_pubkey()
  string += f"  Algorithm: {public_key.type()}\n"
  string += f"  Bits: {public_key.bits()}\n"

  return string



context = ssl.create_default_context()
# context = ssl.SSLContext(ssl.PROTOCOL_TLS)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

def scan(address:str, port:str):
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  
  # Wrap the socket with SSL/TLS
  ssl_sock = context.wrap_socket(sock, server_hostname=address)
  
  returnVal = ""
  
  try:
    # Connect to the server
    ssl_sock.connect((address, port))
    
    ssl_sock.sendall(generate_headers().encode())
    
    cert = ssl_sock.getpeercert(binary_form=True)
    # Receive the response    
    response = b""
    while True:
      
      chunk = ssl_sock.recv(64)
      if not chunk: break
      
      response += chunk

    returnVal = f"Response {response.decode()}" + "\n"
    
    returnVal += "SSL Certificate Information:\n"
    returnVal += get_ssl_cert_info(cert) + "\n"
    returnVal += "######### \n"
      
  except socket.error as e:
    returnVal = f"<Error> (possible connection reset) {e}"
  finally:
    if ssl_sock:
      ssl_sock.close()
  return returnVal