import src.utils as utils

def countScannedIps():
  files = utils.listSubdirs("data/")
  count = 0
  for file in files:
    if file.split("-")[0] != "scan":
      continue
    with open('data/'+file) as f:
      #Count lines in scan files, Masscan has a 2 line header, so hence -2
      count += sum(1 for _ in f)-2
  return count