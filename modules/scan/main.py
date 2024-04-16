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
    "numJobs": 50,
    "maxPingTimeout": 3,
    "output": "./data/scan.txt"
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