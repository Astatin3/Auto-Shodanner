import subprocess
import requests
import random
import importlib
import socket
import struct
import re
from threading import Thread

import nmap

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

  

def scan(host:str, port: int, protocol: str):
  error = False
  results = ""
  for scanner in portScanners:
    if str(scanner.__name__) == f'{protocol}{port}.py':
      scanResults, error = scanner.scan(host, port)
      results += f'[{scanner.__name__}, {host}:{port}] {scanResults}'
      if not error:
        return results
      else:
        results += " Trying default scanner... "
    
  if protocol == "tcp":
    scanResults, error = tcpScanner.scan(host, port)
    results += f'[{tcpScanner.__name__}, {host}:{port}] {scanResults}'
  elif protocol == "udp":
    scanResults, error = udpScanner.scan(host, port)
    results += f'[{udpScanner.__name__}, {host}:{port}] {scanResults}'
  else:
    raise Exception("This should not happen...")

  return results


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
    t = Thread(target = c.run, args=(
      settings['maxPingTimeout'],
      settings['maxNmapTimeout'],
      settings['nmapGroupSize'], 
      portString,))
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



def parseNmapResult(result: object, host: str):
  
  hostname = result.hostname()
  resultstr = f'### {host} ({hostname}) {result.keys()}\n'
  
  # resultstr += f'Location: {scanutils.geolocation(host)}\n'
  
  for protocol in result.all_protocols():
    for portInt in result[protocol].keys():
      port = result[protocol][portInt]
      
      if port['state'] != 'open':
        continue
      
      resultstr += scan(host, portInt, protocol) + "\n"
      
  print(resultstr)


class ScanTask: 
  def __init__(self, threadid: int):
    self.threadid = threadid
    self.running = True
    self.nm = nmap.PortScanner()
      
  def stop(self): 
      self.running = False
        
  def run(self, maxPingTimeout: int, maxNmapTimeout: int, nmapGroupSize: int, portString: str): 
    while self.running:
      ipGroup = []
      while len(ipGroup) < nmapGroupSize and self.running:
        address = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

        pingCommand = f"ping {address} -c 1 -W {maxPingTimeout}"

        try:
          subprocess.check_output(pingCommand.split(" "))
          print(f"{self.threadid} {address}: FOUND {len(ipGroup)+1}/{nmapGroupSize}")
          ipGroup.append(address)
        except subprocess.CalledProcessError:
          # print(f"{self.threadid} {address}: FAIL")
          continue
      print(f'Scanning: {ipGroup}')

      self.nm.scan(hosts=' '.join(ipGroup), ports=portString, arguments="-O --send-eth --privileged -sS --reason -sU")
      
      for address in self.nm.all_hosts():
        parseNmapResult(self.nm[address], address)

      # nmapCommand = f"sudo nmap {address} -O --send-eth --privileged -v -sS --reason -sU -p {portString}"
    
      
      # try:
      #   parseNmapResult(subprocess.check_output(nmapCommand.split(" ")).decode(), address)
      # except subprocess.CalledProcessError:
      #   continue
      