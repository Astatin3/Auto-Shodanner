import libs.scanner as scan
import time

mm = None


def loadSettings(ac):
  ac.send('Scanner-Settings', mm.vars['Scanner-Settings'])


def setSettings(ac, data):
  mm.vars['Scanner-Settings'] = data['data']


def startScanner(ac, data):
  scan.start(mm.vars['Scanner-Settings'])
  
  
def stopScanner(ac, data):
  scan.stop()



def init(moduleMaster):
  global mm
  mm = moduleMaster
  
  mm.vars['Scanner-Settings'] = {
    "range": [[0,0,0,0], [255,255,255,255]],
    "numJobs": 500,
    "maxPingTimeout": 1,
    
    # Port modes:
    # -1: Disable
    #  1: Specify Ports
    #  2: Top N most common ports
    #  3: Related to word
    
    "tcpSettings": {
      "mode": 1,
      "ports": [443]
      # "topCount": 100
      # "relatedString": "http"
    },
    "udpSettings": {
      "mode": -1,
      # "ports": [631, 161, 137, 123, 138]
      "topCount": 50
      # "relatedString": "telnet"
    },
    "runTCP": True,
    "runUDP": False
  } 
  
  mm.addPageEventListener('Scanner-LoadSettings', loadSettings)
  
  mm.addAuthEventListener('Scanner-StartScanner', startScanner)
  mm.addAuthEventListener('Scanner-StopScanner', stopScanner)

def main():
  while True:
    if scan.processStarted():
      print("eee")
      # print(scan.getStdout())
    # print("eee")
    time.sleep(1)