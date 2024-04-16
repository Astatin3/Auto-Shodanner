import subprocess
import random
import socket
import struct
from threading import Thread

import src.utils as utils

threads = []

def start(settings):
  global threads
  utils.makeDir("data/scans")


  for i in range(0,settings['numJobs']):
    c = ScanTask() 
    t = Thread(target = c.run, args=(settings['maxPingTimeout'],))
    t.start()

# def getStdout():
#   global process
#   return subprocess.check_output(process).decode()
  # return "eee" +  process.stdout.readline()


def stop():
  global threads
  for thread in threads:
    thread.stop()
  threads = []
  print("\n\nstopped Scanner!")


def processStarted():
  global threads
  return len(threads) != 0;





class ScanTask: 
  def __init__(self):
    self.running = True
      
  def stop(self): 
      self.running = False
        
  def run(self, maxPingTimeout): 
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