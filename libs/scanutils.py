import subprocess
import requests
import src.utils as utils
import os
import re
import geoip2.database

import socket
import struct
import time

def checksum(data):
    """
    Calculate the checksum of the ICMP packet data.
    """
    sum = 0
    for i in range(0, len(data), 2):
      sum += (data[i] << 8) + data[i+1]
    sum = (sum & 0xffff) + (sum >> 16)
    sum = ~sum & 0xffff
    return sum

import time
import random
import select
import array


def ping_chksum(packet:bytes):
  if len(packet) % 2 != 0:
    packet += b'\0'

  res = sum(struct.unpack("!%sH" % (len(packet) // 2), packet))
  res = (res >> 16) + (res & 0xffff)
  res += res >> 16

  return (~res) & 0xffff


def ping(host:str, timeout:int, sock):
  returnVal = (False, -1)
  try:
    # Craft the ICMP echo request packet
    packet_id = int(time.time() * 1000) & 0xFFFF
    header = struct.pack("bbHHh", 8, 0, 0, packet_id, 1)
    data = b"ping"
    checksum = ping_chksum(header + data)
    header = struct.pack("bbHHh", 8, 0, socket.htons(checksum), packet_id, 1)
    packet = header + data

    # Send the ICMP echo request
    sock.sendto(packet, (host, 1))

    # Receive the ICMP echo reply
    start_time = time.time()
    while True:
      remaining_time = timeout - (time.time() - start_time)
      if remaining_time <= 0:
        return False
      ready = select.select([sock], [], [], remaining_time)
      if ready[0]:
        data, addr = sock.recvfrom(1024)
        icmp_header = data[20:28]
        type, code, checksum, p_id, sequence = struct.unpack("bbHHh", icmp_header)
        if p_id == packet_id:
          return returVal

  except:pass
  return returnVal
  #     return False




# def countScannedIps():
#   files = utils.listSubdirs("data/")
#   count = 0
#   for file in files:
#     if file.split("-")[0] != "scan":
#       continue
#     with open('data/'+file) as f:
#       #Count lines in scan files, Masscan has a 2 line header, so hence -2
#       count += sum(1 for _ in f)-2
#   return count

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



def geolocation(ip_address: str):
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

def parseIpList(path: str):
  with open(path, "r") as f:
    lines = f.readlines()
    return [line.rstrip() 
            for line in lines 
            if not line.startswith('#') and not line.startswith('\n')
            ]


def ipToInt(ip: str):
  octets = [int(n) for n in ip.split('.')]
  return (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]


def ipInCIDR(ip: str, ip_CIDR: str):
  range_parts = ip_CIDR.split('/')
  range_mask = int(range_parts[1])

  range_mask_num = (0xFFFFFFFF << (32 - range_mask)) & 0xFFFFFFFF

  return (ipToInt(ip) & range_mask_num) == (ipToInt(range_parts[0]) & range_mask_num)


def ipInRange(ip: str, ip_range: str):
  ip_int = ipToInt(ip)
  start_ip_int, end_ip_int = [ipToInt(ip) for ip in ip_range.split('-')]
  
  return start_ip_int <= ip_int <= end_ip_int


def ipInArray(ip: str, ipRangeArray: list):
  for ipRange in ipRangeArray:
    if "/" in ipRange:
      if ipInCIDR(ip, ipRange):
        return True
    elif "-" in ipRange:
      if ipInRange(ip, ipRange):
        return True
    elif ip == ipRange:
      return True
  return False