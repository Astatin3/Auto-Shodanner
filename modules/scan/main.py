import libs.scanner as scan
import time

mm = None


def loadSettings(ac):
  ac.send('Scanner-Settings', mm.vars['Scanner-Settings'])


def setSettings(ac, data):
  if not mm.userInGroup(ac, 'Admins'):
    mm.sendPopupError(ac.rawClient, "Error", "You are not authorised")
    return
  
  data = data['data']
  valid = True
  
  valid = valid and isinstance(data['numJobs'], int)
  valid = valid and isinstance(data['maxPingTimeout'], int)
  valid = valid and isinstance(data['maxNmapTimeout'], int)
  valid = valid and isinstance(data['nmapGroupSize'], int)
  
  valid = valid and isinstance(data['tcpSettings'], dict)
  valid = valid and isinstance(data['udpSettings'], dict)
  
  valid = valid and isinstance(data['tcpSettings']['mode'], int)
  valid = valid and isinstance(data['udpSettings']['mode'], int)
  
  if valid:
    for obj in [data['tcpSettings'], data['udpSettings']]:
      match obj['mode']:
        case -1:
          pass
        case 1:
          valid = valid and isinstance(obj['mode'], int)
          valid = valid and isinstance(obj['ports'], list)
          if valid:
            valid = valid and all(isinstance(val, int) for val in obj['ports'])
        case 2:
          valid = valid and isinstance(obj['topCount'], int)
        case 3:
          valid = valid and isinstance(obj['relatedString'], str)
        case _:
          valid = False
      
  if valid:
    print(data)
    mm.vars['Scanner-Settings'] = data
  else:
    mm.sendPopupError(ac.rawClient, "Error", "There is an error in the config.")


def onStats(stats):
  # print(stats)
  for ac in mm.authServer.clients:
    if ac.currentPage == "/main/dashboard":
      ac.send("Scanner-Metrics", stats)


def startScanner(ac, data):
  mm.sendPopupSuccess(ac.rawClient, "Scanner", "Scanner Started!")
  scan.start(mm.vars['Scanner-Settings'], onStats)
  
  
def stopScanner(ac, data):
  mm.sendPopupSuccess(ac.rawClient, "Scanner", "Scanner Stopped!")
  scan.stop()


def init(moduleMaster):
  global mm
  mm = moduleMaster
  
  mm.vars['Scanner-Settings'] = {
    "numJobs": 500,
    "maxPingTimeout": 3,
    "maxNmapTimeout": 2,
    "nmapGroupSize": 10,
    
    # Port modes:
    # -1: Disable
    #  1: Specify Ports
    #  2: Top N most common ports
    #  3: Related to word
    
    "tcpSettings": {
      "mode": 2,
      "ports": [22, 80, 443],
      "topCount": 100,
      "relatedString": "http"
    },
    "udpSettings": {
      "mode": -1,
      "ports": [631, 161, 137],
      "topCount": 100,
      "relatedString": "telnet"
    }
  } 
  
  mm.addPageEventListener('/Scan/Scan', loadSettings)
  mm.addAuthEventListener('Scanner-SetSettings', setSettings)
  
  mm.addAuthEventListener('Scanner-StartScanner', startScanner)
  mm.addAuthEventListener('Scanner-StopScanner', stopScanner)

def main():
  pass