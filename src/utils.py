import os
import json
import string
import random
from hashlib import sha256
from datetime import datetime

from sys import platform

import subprocess

def getRoot(path):
  rootdir = os.getcwd() + f'/{path}'

  if platform in ['nt', 'win32', 'win64']:
    rootdir = rootdir.split(':')[1].replace('\\', '/')
  
  return rootdir

def pathExists(path):
  return os.path.exists(path)

def makeDir(path):
  if not os.path.exists(path):
    os.makedirs(path)

def listSubdirs(folder):
  if os.path.exists(folder):
    return os.listdir(folder)
  else:
    return []

def writeFile(path, data):
    if not os.path.exists(path):
        with open(path, mode='a'): pass
    with open(path, 'w') as f:
        f.write(data)

def readFile(path):
    if not os.path.exists(path):
        return ''
    try:
        with open(path) as f:
            return f.read()
    except:
        return ''

def delFile(path):
  if os.path.exists(path):
    os.remove(path)

def getUnixTime():
  return round((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds() * 1000)

def hash(data):
  return sha256(data.encode('utf-8')).hexdigest().upper()

def getatribinarr(arr, atribname, atrib):
  for i in range(0,len(arr),1):
      if getattr(arr[i], atribname) == atrib:
          return arr[i]
  return None

def randID(length):
  letters = string.hexdigits
  return ''.join(random.choice(letters) for i in range(length))

def genDefaultAccounts():
  userPassword = randID(16)
  adminPassword = randID(16)

  print('#################################################')
  print('New Credentials - THESE ONLY WILL BE PRINTED ONCE')
  print('########')
  print('Username: User')
  print(f'Password: {userPassword}')
  print('########')
  print('Username: Admin')
  print(f'Password: {adminPassword}')
  print('#################################################')

  time = getUnixTime()

  return json.dumps(
    [
      {
        'username': 'User',
        'permGroups': [
          'Users'
        ],
        'id': randID(16),
        'created': time,
        'passwordUpdated': time,
        'sha256passwordhash': hash(userPassword)
      },
      {
        'username': 'Admin',
        'permGroups': [
          'Users',
          'Admins'
        ],
        'id': randID(16),
        'created': time,
        'passwordUpdated': time,
        'sha256passwordhash': hash(adminPassword)
      }
    ], sort_keys=True, indent=2)

def genKey(path):
  subprocess.run(['openssl', 'genrsa', '-out', f'{path}ssl.key', '2048'])

def genCert(path):
  writeFile(f'{path}/ssl.cnf', 
"""[req]
default_bits = 2048
prompt = no
default_md = sha256
encrypt_key = no
distinguished_name = dn

[dn]
C = ID
O = Local Digital Cert Authority
OU = www.ca.local
CN = Self-Signed Root CA
""")

  subprocess.run(['openssl', 'req', '-new', '-key', f'{path}ssl.key', '-out', f'{path}ssl.csr', '-config', f'{path}ssl.cnf'])
  subprocess.run(['openssl', 'x509', '-req', '-days', '36500', '-in', f'{path}ssl.csr', '-signkey', f'{path}ssl.key', '-out', f'{path}ssl.crt'])

  delFile(f'{path}ssl.cnf')
  delFile(f'{path}ssl.csr')