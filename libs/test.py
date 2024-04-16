import subprocess
import random
import socket
import struct
from threading import Thread

maxPingTimeout = 3

class ScanTask: 
  def __init__(self):
    self.running = True
      
  def terminate(self): 
      self.running = False
        
  def run(self): 
    while True:
      address = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

      pingCommand = f"ping {address} -c 1 -W {maxPingTimeout}"

      try:
        subprocess.check_output(pingCommand.split(" "))
        # print(f"{address}: FOUND")
      except subprocess.CalledProcessError:
        # print(f"{address}: FAIL")
        continue
      
      nmapCommand = f"sudo nmap {address} -O --send-eth --privileged -v -sS"
      
      try:
        print(subprocess.check_output(nmapCommand.split(" ")).decode())
      except subprocess.CalledProcessError:
        continue

threads = []

for i in range(0,500):
  c = ScanTask() 
  t = Thread(target = c.run)
  t.start()
  # threads.push(c)
  
for thread in threads:
  thread.join()