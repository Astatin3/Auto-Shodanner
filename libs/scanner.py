import subprocess
import requests
import random
import importlib
import socket
import struct
import re
import zlib
import base64
import shutil
import resource
from threading import Thread

import nmap

import src.utils as utils
import libs.scanutils as scanutils

import libs.scanners.tcpScanner as tcpScanner
import libs.scanners.udpScanner as udpScanner

portScanners = []
tasks = []
excludeRanges = []

downIps = 0
upIps = 0
globalSettings = {}

for script in utils.listSubdirs(utils.getRoot("libs/scanners/")):
  if not script.endswith(".py"): continue
  if script == "tcpScanner.py": continue
  if script == "udpScanner.py": continue
  
  spec = importlib.util.spec_from_file_location(script, utils.getRoot(f'libs/scanners/{script}'))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  portScanners.append(module)
  
  print(f'Imported: {utils.getRoot(f"libs/scanners/{module.__name__}")}')

  
soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (hard_limit, hard_limit))



def start(settings):
  global tasks
  global globalSettings
  globalSettings = settings
  
  if processStarted(): return
  
  print("\n\nStarted Scanner!")
  print("\n\n\n", end='')
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

  global excludeRanges
  excludeRanges = scanutils.parseIpList(utils.getRoot("exclude.conf"))

  for i in range(0,settings['numJobs']):
    c = ScanTask(i+1)
    t = Thread(target = c.run, args=(
      settings['maxPingTimeout'],
      settings['maxNmapTimeout'],
      settings['nmapGroupSize'], 
      portString,))
    t.start()
    tasks.append(c)


def stop():
  if not processStarted(): return
  global tasks
  for task in tasks:
    task.stop()
  tasks = []
  print("\n\nstopped Scanner!")


def processStarted():
  global tasks
  return len(tasks) != 0;


class hostScanDetail:
  def __init__(self):
    self.address = None
    self.hostname = None
    # self.




def parseNmapResult(result: object, host: str):
  
  # dict_keys(['hostnames', 'addresses', 'vendor', 'status', 'tcp', 'portused', 'osmatch'])
  
  resultstr = '### Start Host Info ###\n'
  
  resultstr += f'Address: {host}\n'
  resultstr += 'Status: Up\n'
  resultstr += f'Hostname: {result.hostname()}\n'
  resultstr += f'Location: {scanutils.geolocation(host)}\n'

  osInfo = []
  if 'osmatch' in result:
    for os in result['osmatch']:
      osInfo.append([os["accuracy"], os["name"]])

  resultstr += f'OS-Info: {osInfo}\n'

  for protocol in result.all_protocols():
    for portInt in result[protocol].keys():
      port = result[protocol][portInt]
      
      resultstr += f'Port: {portInt},{protocol},{port["state"]},{port["reason"]}'
      
      if port['state'] == 'open':
        data = scan(host, portInt, protocol)
        compressedData = base64.b64encode(zlib.compress(data.encode())).decode('ASCII')
        
        resultstr += f',{compressedData}'
      
      resultstr += "\n"

  resultstr += '### End Host Info ###\n'
      
  print(resultstr, end='')

def addOfflineHost(host:str):
  string = '### Start Host Info ###\n' + \
          f'Address: {host}\n' + \
          f'Status: Down\n' + \
           '### End Host Info ###\n'
  # print(string, end='')
            
  


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


# def saveData()


def printBar(percentage: float, cols: int):
  return ("#" * round(percentage*cols)) + ("-" * round((1-percentage) * cols))



def printIndicator():
  return
  hostSearchingCount = 0
  nmapScanningCount = 0
  furtherScanningCount = 0
  for task in tasks:
    match task.status:
      case 1:
        hostSearchingCount += 1
      case 2:
        nmapScanningCount += 1
      case 3:
        furtherScanningCount += 1
  
  width = shutil.get_terminal_size((80, 20)).columns
  global globalSettings
  numJobs = int(globalSettings['numJobs'])
  
  print("\033[F\033[F\033[F" +
        f"P: {printBar(hostSearchingCount/numJobs,(width-3))}\n" +
        f"N: {printBar(nmapScanningCount/numJobs,(width-3))}\n" +
        f"S: {printBar(furtherScanningCount/numJobs,(width-3))}\n", end="")
  # print(f"1: {hostSearchingCount}, " +
  #       f"2: {nmapScanningCount}, " +
  #       f"3: {furtherScanningCount}", end="\r")

class ScanTask: 
  def __init__(self, threadid: int):
    self.threadid = threadid
    self.running = True
    self.nm = nmap.PortScanner()
    self.pingsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    self.status = None
      
  def stop(self): 
    self.running = False
        
  def run(self, maxPingTimeout: int, maxNmapTimeout: int, nmapGroupSize: int, portString: str): 
    
    global upIps
    global downIps
    global excludeRanges
    

    while self.running:
      
      self.status = 1
      printIndicator()
      ipGroup = []
      
      while len(ipGroup) < nmapGroupSize and self.running:
        address = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

        if scanutils.ipInArray(address, excludeRanges):
          # print(f"Tried {address}")
          continue

        if scanutils.ping(address, maxPingTimeout, self.pingsock):
          # print(f"{self.threadid} {address}: FOUND {len(ipGroup)+1}/{nmapGroupSize}")
          upIps += 1
          ipGroup.append(address)
        else:
          addOfflineHost(address)
          downIps += 1
          # print(f"{self.threadid} {address}: FAIL")
          continue

      if not self.running: return

      self.status = 2
      printIndicator()

      self.nm.scan(hosts=' '.join(ipGroup), ports=portString, arguments="-O --send-eth --privileged -sS --reason -sU")
      
      if not self.running: return
      
      self.status = 3
      printIndicator()

      for address in self.nm.all_hosts():
        parseNmapResult(self.nm[address], address)
