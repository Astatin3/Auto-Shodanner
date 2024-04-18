import subprocess
import requests
import src.utils as utils
import os
import re
import geoip2.database

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

def getMostCommon(protocol: str, n: int):
  nmap_services_file = "/usr/share/nmap/nmap-services"
  
  if not os.path.exists(nmap_services_file):
    print(f"Error: {nmap_services_file} not found.")
    return []
  
  ports = []
  with open(nmap_services_file, "r") as file:
    for line in file:
      if line.startswith("#"):
        continue
      
      fields = line.split()
      if len(fields) >= 3:
        port_info = fields[1]
        port, proto = port_info.split("/")
        frequency = float(fields[2])
        
        if proto.lower() == protocol.lower():
          ports.append((int(port), frequency))  

  most_common_ports = sorted(ports, key=lambda x: x[1], reverse=True)[:n]
  return [port[0] for port in most_common_ports]




def portsRelatedTo(protocol: str, search_string: str):
  nmap_services_file = "/usr/share/nmap/nmap-services"
  
  if not os.path.exists(nmap_services_file):
    print(f"Error: {nmap_services_file} not found.")
    return []
  
  ports = []
  with open(nmap_services_file, "r") as file:
    for line in file:
      if line.startswith("#"):
        continue
      
      fields = line.split("#")
      port_info = fields[0].strip()
      description = fields[1].strip() if len(fields) >= 2 else ""
      
      port_fields = port_info.split()
      if len(port_fields) >= 2:
        port, proto = port_fields[1].split("/")
        service_name = port_fields[0]
        
        if (
          proto.lower() == protocol.lower() and
          (search_string.lower() in description.lower() or search_string.lower() in service_name.lower())
        ):
          ports.append(int(port))
  
  return ports


def getPorts(nmapResult: str):
  lines = nmapResult.split("\n")

  row_pattern = re.compile(r'\d+/(tcp|udp)\s+\S+')

  portInfo = []

  for line in lines:
    if row_pattern.match(line):
      columns = line.split(None, 3)
      if len(columns) == 4:
        portInfo.append(columns)

  return portInfo



def getHostname(nmapResult: str):
  hostnamePattern = re.compile(r"Nmap scan report for ([\w.-]+)\s+\(([\d.]+)\)")
  hostnameList = hostnamePattern.findall(nmapResult)
  return hostnameList[0][0] if len(hostnameList) != 0 else ""



# Download geolocation databases
utils.makeDir(utils.getRoot("data"))

CITY_DB_PATH = utils.getRoot("data/GeoLite2-City.mmdb")
if not utils.pathExists(CITY_DB_PATH):
  print("Downloading GeoLite2-City.mmdb database...")
  open(CITY_DB_PATH, 'wb').write(
    requests.get("https://github.com/P3TERX/GeoLite.mmdb/releases/download/2024.04.16/GeoLite2-City.mmdb").content
  )

COUNTRY_DB_PATH = utils.getRoot("data/GeoLite2-Country.mmdb")
if not utils.pathExists(COUNTRY_DB_PATH):
  print("Downloading GeoLite2-Country.mmdb database...")
  open(COUNTRY_DB_PATH, 'wb').write(
    requests.get("https://github.com/P3TERX/GeoLite.mmdb/releases/download/2024.04.16/GeoLite2-Country.mmdb").content
  )

ASN_DB_PATH = utils.getRoot("data/GeoLite2-ASN.mmdb")
if not utils.pathExists(ASN_DB_PATH):
  print("Downloading GeoLite2-ASN.mmdb database...")
  open(ASN_DB_PATH, 'wb').write(
    requests.get("https://github.com/P3TERX/GeoLite.mmdb/releases/download/2024.04.16/GeoLite2-ASN.mmdb").content
  )



def geolocation(ip_address):
  try:
    # Attempt to retrieve city-level information
    with geoip2.database.Reader(CITY_DB_PATH) as reader:
      response = reader.city(ip_address)
      return {
        'ip': ip_address,
        'city': response.city.name,
        'subdivision': response.subdivisions.most_specific.name,
        'country': response.country.name,
        'continent': response.continent.name,
        'latitude': response.location.latitude,
        'longitude': response.location.longitude,
        'postal_code': response.postal.code,
        'time_zone': response.location.time_zone
        }
  except geoip2.errors.AddressNotFoundError:
    try:
      # Attempt to retrieve country-level information
      with geoip2.database.Reader(COUNTRY_DB_PATH) as reader:
        response = reader.country(ip_address)
        return {
          'ip': ip_address,
          'country': response.country.name,
          'continent': response.continent.name
        }
    except geoip2.errors.AddressNotFoundError:
      try:
        # Attempt to retrieve ASN information
        with geoip2.database.Reader(ASN_DB_PATH) as reader:
          response = reader.asn(ip_address)
          return {
            'ip': ip_address,
            'asn': response.autonomous_system_number,
            'org': response.autonomous_system_organization
          }
      except geoip2.errors.AddressNotFoundError:
        return {
          'ip': ip_address,
          'error': 'No geolocation data found'
        }
