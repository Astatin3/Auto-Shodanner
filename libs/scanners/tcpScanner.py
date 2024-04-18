import socket
import time

def scan(address:str, port:int, timeout:int=5):
  returnVal = ""
  error = False
  
  client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  try:
    client_socket.connect((address, port))
    client_socket.settimeout(timeout)
    start_time = time.time()
    

    while time.time() - start_time < timeout:
      try:
        
        data = client_socket.recv(64)
        if not data: break
        returnVal += data.decode()
        
      except socket.timeout:
        break
    
  except Exception as e:
    returnVal += f'<error {e}>'
    error = True
  finally:
    client_socket.close()
  
  return returnVal, error