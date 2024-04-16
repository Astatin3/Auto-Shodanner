import src.web as web
import src.utils as utils
import src.modules as modules
from sys import argv

webserv = web.webserv()
moduleMaster = modules.moduleMaster()


def main():

  if not utils.pathExists('data'):
    utils.makeDir('data') 

  if not utils.pathExists('data/creds.json'):
    if input("No credentials file was found, \nwould you like to create one? (Y/n): ").lower() in ["yes", "y", ""]:
      utils.writeFile('data/creds.json', utils.genDefaultAccounts()) 

  if webserv.secure and ( not utils.pathExists('data/ssl.crt') or not utils.pathExists('data/ssl.key') ):
    if input("No ssl key/cert was found, \nwould you like to create them? (Y/n): ").lower() in ["yes", "y", ""]:

      if not utils.pathExists('data/ssl.key'):
        utils.genKey(utils.getRoot('data/'))

      if not utils.pathExists('data/ssl.crt'):
        utils.genCert(utils.getRoot('data/'))

  moduleMaster.addModules(webserv)
  webserv.init()
  moduleMaster.initModules(webserv)
  webserv.start()
  moduleMaster.runModules()

  # for m in modules:
  #   m.module.main()

def printHelp():
  print("""
  Modulator usage:

  -h -? --help     - Print this help information
  -v --verbose     - Print verbose information, default: false
  -u --unsecure    - Use http instead of https, default: false
  -p --port <int> - Set port of the webserver, default: 80 or 44
  -h --host <str> - Set host of the webserver, default: 0.0.0.0

  --defaultTab <str> - Set the default tab on visit, default: 'main'
  --title <str>      - Set the title of the html pages, default: 'Modulator'

  Examples:

  $ python3 ./main.py
  $ python3 ./main.py -vo 127.0.0.1
  $ python3 ./main.py -p 12345 -h 192.168.0.123
  """)

if __name__ == '__main__':

  i = 1

  while i < len(argv):
    arg = argv[i]
    sargs = list(arg)
    if sargs[0] == '-' and sargs[1] == '-':
      match arg:
        case '--help':
          printHelp()
          exit()
        case '--verbose':
          webserv.verbose = True
          i+=1; continue
        case '--unsecure':
          webserv.secure = False
          if webserv.port == 443:
            webserv.port = 80
          i+=1; continue
        case '--port':
          webserv.port = int(argv[i+1])
          i+=2; continue
        case '--host':
          webserv.host = str(argv[i+1])
          i+=2; continue
        case '--defaultTab':
          webserv.defaultTab = str(argv[i+1])
          i+=2; continue
        case '--title':
          webserv.title = str(argv[i+1])
          i+=2; continue
    elif sargs[0] == '-':
      for sarg in sargs:
        match sarg:
          case 'h' | '?':
            printHelp()
            exit()
          case 'v':
            webserv.verbose = True
          case 'u':
            webserv.secure = False
            if webserv.port == 443:
              webserv.port = 80
          case 'p':
            webserv.port = int(argv[i+1])
            i+=1; continue
          case 'o':
            webserv.host = str(argv[i+1])
            i+=1; continue

    i += 1

  main()
