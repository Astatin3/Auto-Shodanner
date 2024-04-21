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
from threading import Thread, Timer

import nmap

import src.utils as utils
import src.jsonpack as jsonpack
import libs.scanutils as scanutils

import libs.scanners.tcpScanner as tcpScanner
import libs.scanners.udpScanner as udpScanner

portScanners = []
tasks = []
excludeRanges = []

upIps = 0
downIps = 0
extendedIps = 0

upIpsPS = 0
downIpsPS = 0
extendedIpsPS = 0

countScannedBeforeStart = 0

running = False
globalSettings = {}
onStatsFunc = None


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



def start(settings, onStats):
  if processStarted(): return
  global tasks
  global globalSettings
  globalSettings = settings
  
  global onStatsFunc
  onStatsFunc = onStats
  
  global upIps
  global downIps
  global extendedIps
  upIps = 0
  downIps = 0
  extendedIps = 0
  
  global upIpsPS
  global downIpsPS
  global extendedIpsPS
  upIpsPS = 0
  downIpsPS = 0
  extendedIpsPS = 0
  
  global countScannedBeforeStart
  countScannedBeforeStart = scanutils.countScannedIps()
  
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

  global running
  running = True

  for i in range(0,settings['numJobs']):
    c = ScanTask(i+1)
    t = Thread(target = c.run, args=(
      settings['maxPingTimeout'],
      settings['maxNmapTimeout'],
      settings['nmapGroupSize'], 
      portString,))
    t.start()
    tasks.append(c)
    
  statsTimer()


def stop():
  if not processStarted(): return
  global tasks
  global running
  tasks = []
  running = False
  print("\n\nstopped Scanner!")


def processStarted():
  global tasks
  return len(tasks) != 0;


class hostScanDetail:
  def __init__(self):
    self.address = None
    self.hostname = None
    # self.

def statsTimer():
  if running:
    Timer(1.0, statsTimer).start()

  global upIps
  global downIps
  global extendedIps
  
  global upIpsPS
  global downIpsPS
  global extendedIpsPS
  global numJobs
  global countScannedBeforeStart

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

  stats = {
    "upIps": upIps,
    "downIps": downIps,
    "extendedIps": extendedIps,
    
    "upIpsPS": upIpsPS,
    "downIpsPS": downIpsPS,
    "extendedIpsPS": extendedIpsPS,
    
    "hostSearchingCount": hostSearchingCount,
    "nmapScanningCount": nmapScanningCount,
    "furtherScanningCount": furtherScanningCount,
    "countScannedBeforeStart": countScannedBeforeStart,
    "numJobs": int(globalSettings['numJobs'])
    
  }
  upIpsPS = 0
  downIpsPS = 0
  extendedIpsPS = 0

  
  onStatsFunc(stats)



def parseNmapResult(result: object, host: str):
  
  # dict_keys(['hostnames', 'addresses', 'vendor', 'status', 'tcp', 'portused', 'osmatch'])
  
  # resultstr = '### Start Host Info ###\n'
  # location = scanutils.geolocation(host)
  # location.pop('ip', None) # The geolocation string does not have to include the IP again
  # compressedLocationData = base64.b64encode(
  #   zlib.compress(
  #     jsonpack.pack(location).encode())
  #   ).decode('ASCII')
  
  resultstr = f'{host},1,{result.hostname()}'

  osInfo = []
  if 'osmatch' in result:
    for os in result['osmatch']:
      osInfo.append([int(os["accuracy"]), os["name"]])

  resultstr += f',{osInfo}'

  resultstr += ',['

  first = True
  for protocol in result.all_protocols():
    for portInt in result[protocol].keys():
      port = result[protocol][portInt]

      if not first:
        resultstr += ','
      first = False

      resultstr += f'[{portInt},{protocol},{port["state"]},{port["reason"]}'
      
      if port['state'] == 'open':
        data = scan(host, portInt, protocol)
        compressedData = base64.b64encode(zlib.compress(data.encode())).decode('ASCII')

        resultstr += f',{compressedData}'
      
      resultstr += "]"
      
  resultstr += "]"
  
  if len(result.all_protocols()) > 0:
    global extendedIps
    global extendedIpsPS
    extendedIps += 1
    extendedIpsPS += 1
  
  # print(resultstr)
      
  write(host, resultstr)
  
  

def addOfflineHost(host:str):
  write(host, f'{host},0')
  # print(string, end='')
            
  
def write(host:str, data:str):
  split = host.split(".")
  
  utils.makeDir(utils.getRoot(f"data/scans/{split[0]}/"))

  with open(utils.getRoot(f"data/scans/{split[0]}/{split[1]}.txt"), "a") as file:
    file.write(data + "\n")



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


class ScanTask: 
  def __init__(self, threadid: int):
    self.threadid = threadid
    self.nm = nmap.PortScanner()
    self.pingsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    self.status = None
        
  def run(self, maxPingTimeout: int, maxNmapTimeout: int, nmapGroupSize: int, portString: str): 
    
    global upIps
    global downIps
    global extendedIps
    
    global upIpsPS
    global downIpsPS
    global extendedIpsPS
    
    global excludeRanges
    global running
    
    
    

    while running:
      
      self.status = 1
      ipGroup = []
      
      while len(ipGroup) < nmapGroupSize and running:
        address = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

        if scanutils.ipInArray(address, excludeRanges):
          # print(f"Tried {address}")
          continue

        if scanutils.ping(address, maxPingTimeout, self.pingsock):
          # print(f"{self.threadid} {address}: FOUND {len(ipGroup)+1}/{nmapGroupSize}")
          upIps += 1
          upIpsPS += 1
          ipGroup.append(address)
        else:
          addOfflineHost(address)
          downIps += 1
          downIpsPS += 1
          # print(f"{self.threadid} {address}: FAIL")
          continue

      if not running: return

      self.status = 2

      self.nm.scan(hosts=' '.join(ipGroup), ports=portString, arguments="-O --send-eth --privileged -sS --reason -sU")
      
      if not running: return
      
      self.status = 3

      for address in self.nm.all_hosts():
        parseNmapResult(self.nm[address], address)
