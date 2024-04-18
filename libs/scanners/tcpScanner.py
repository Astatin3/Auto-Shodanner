import socket
import time

def scan(address:str, port:int, timeout:int=5):
  returnVal = ""
  
  client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  try:
    client_socket.connect((address, port))
    client_socket.settimeout(timeout)
    start_time = time.time()
    
    outBytes = b''

    while time.time() - start_time < timeout:
      try:
        
        data = client_socket.recv(64)
        if not data: break
        outBytes += data
        
      except socket.timeout:
        break

    returnVal = f'({address}:{port}) Recieved: {outBytes.decode()}'
    
  except socket.error as e:
    print(f"Error: {e}")
    returnVal = f'({address}:{port}) Recieved: <error>'
  finally:
    client_socket.close()
  
  return returnVal