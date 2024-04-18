import libs.scanners.tcp80

def scan(host:str, port:int):
  return tcp80.scan(host, port)