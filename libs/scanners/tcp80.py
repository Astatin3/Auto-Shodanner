import random
import socket
from faker import Faker

def generate_headers():
  fake = Faker()
  return [
    f"User-Agent: {fake.user_agent()}",
    f"Accept: {fake.mime_type()}",
    f"Accept-Language: {fake.language_code()},{fake.language_code()};q=0.9",
    f"Accept-Encoding: {fake.mime_type()}, {fake.mime_type()}, {fake.mime_type()}",
    f"Referer: {fake.url()}",
    f"Connection: {random.choice(['keep-alive', 'close'])}",
    f"Cache-Control: {random.choice(['no-cache', 'max-age=0'])}",
    f"Pragma: {random.choice(['no-cache', ''])}",
  ]

def scan(host:str, port:int):
  returnVal = ""
  try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    headers = generate_headers()
    request = "GET / HTTP/1.1\r\n"
    request += "Host: " + host + "\r\n"
    request += "\r\n".join(headers)
    request += "\r\n\r\n"

    client_socket.send(request.encode())

    response = b""
    while True:
      
      chunk = client_socket.recv(64)
      
      if not chunk: break
      
      response += chunk

    returnVal = "Response: " + response.decode()

  except:
    returnVal = "<Error> (possible connection reset)"
  finally:
    if client_socket:
      client_socket.close()
  
  return returnVal