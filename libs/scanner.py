import subprocess
import requests
import random
import importlib
import socket
import struct
import re
from threading import Thread

import src.utils as utils
import libs.scanutils as scanutils

import libs.scanners.tcpScanner as tcpScanner
import libs.scanners.udpScanner as udpScanner

portScanners = []
tasks = []

for script in utils.listSubdirs(utils.getRoot("libs/scanners/")):
  if not script.endswith(".py"): continue
  if script == "tcpScanner.py": continue
  if script == "udpScanner.py": continue
  
  spec = importlib.util.spec_from_file_location(script, utils.getRoot(f'libs/scanners/{script}'))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  portScanners.append(module)
  
  print(f'Imported: {utils.getRoot(f"libs/scanners/{module.__name__}")}')

  

def getScanner(port: int, protocol: str):
  for scanner in portScanners:
    if str(scanner.__name__) == f'{port}.{protocol}.py':
      return scanner
  if protocol == "tcp":
    return tcpScanner
  elif protocol == "udp":
    return udpScanner
  else:
    raise Exception("This should not happen...")



def start(settings):
  global tasks
  
  if processStarted(): return
  
  print("\n\nStarted Scanner!")
  utils.makeDir("data/scans")

  portString = ""

  match settings['udpSettings']['mode']:
    case -1:
      pass
    case 1:
      portString += "U:" + ",".join(map(str, settings['udpSettings']['ports']))
    case 2:
      portString += "U:" + ",".join(map(str, scanutils.getMostCommon('udp', settings['udpSettings']['topCount'])))
    case 3:
      portString += "U:" + ",".join(map(str, scanutils.portsRelatedTo('udp', settings['udpSettings']['relatedString'])))
      
  if settings['tcpSettings']['mode'] != -1 and settings['udpSettings']['mode'] != -1:
    portString += ","
    
  match settings['tcpSettings']['mode']:
    case -1:
      pass
    case 1:
      portString += "T:" + ",".join(map(str, settings['tcpSettings']['ports']))
    case 2:
      portString += "T:" + ",".join(map(str, scanutils.getMostCommon('tcp', settings['tcpSettings']['topCount'])))
    case 3:
      portString += "T:" + ",".join(map(str, scanutils.portsRelatedTo('tcp', settings['tcpSettings']['relatedString'])))


  for i in range(0,settings['numJobs']):
    c = ScanTask(i)
    t = Thread(target = c.run, args=(settings['maxPingTimeout'],portString,))
    t.start()
    tasks.append(c)


def stop():
  global tasks
  for task in tasks:
    task.stop()
  tasks = []
  print("\n\nstopped Scanner!")


def processStarted():
  global tasks
  return len(tasks) != 0;



def parseNmapResult(result: str, address: str):
  return
  
  
  ports = scanutils.getPorts(result)
  hostname = scanutils.getHostname(result)
  resultstr = f'### {address} ({hostname}) {ports}\n'
  
  # resultstr += f'Location: {scanutils.geolocation(address)}\n'
  
  for port in ports:
    if port[1] != 'open':
      continue
    # resultstr += str(port) + '\n'

    portInt = int(port[0].split("/")[0])
    protocol = port[0].split("/")[1]
    scanner = getScanner(portInt, protocol)
    
    resultstr += f'[{scanner.__name__}]\n'
    resultstr += scanner.scan(address, portInt) + "\n"
    
  # print(resultstr)


class ScanTask: 
  def __init__(self, threadid: int):
    self.threadid = threadid
    self.running = True
      
  def stop(self): 
      self.running = False
        
  def run(self, maxPingTimeout: int, portString: str): 
    while self.running:
      address = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

      pingCommand = f"ping {address} -c 1 -W {maxPingTimeout}"

      try:
        subprocess.check_output(pingCommand.split(" "))
        # print(f"{self.threadid} {address}: FOUND")
      except subprocess.CalledProcessError:
        # print(f"{self.threadid} {address}: FAIL")
        continue


      nmapCommand = f"sudo nmap {address} -O --send-eth --privileged -v -sS --reason -sU -p {portString}"
    
      
      try:
        parseNmapResult(subprocess.check_output(nmapCommand.split(" ")).decode(), address)
      except subprocess.CalledProcessError:
        continue
      