import libs.scanutils as scanutils
mm = None

def dashboardMetrics(ac):
  ac.send('Scanner-Metrics', {
    "scanCount": scanutils.countScannedIps()
  })

def init(moduleMaster):
  global mm
  mm = moduleMaster

  mm.addPageEventListener('/main/dashboard', dashboardMetrics)

  # User settings
  mm.addAuthEventListener('logout', logout)
  mm.addAuthEventListener('unauth', unauth)
  
  mm.addAuthEventListener('passwordChangeRequest', changePassword)
  
  # Admin settings
  mm.addAuthEventListener('addUserRequest', addUser)
  mm.addAuthEventListener('disconnectAllSessions', disconnectAllSessions)
  mm.addAuthEventListener('changeGroupsRequest', changeGroups)
  mm.addAuthEventListener('deleteUserRequest', deleteUser)
  # mm.addAuthEventListener('login', disconnectAllSessions)
  
  mm.addPageEventListener('/main/User', loadSessions)
  mm.addPageEventListener('/main/Admin', loadSessionsAdmin)



def main():
  pass



def logout(ac, data):
  mm.unauth(ac)



def unauth(ac, data):
  removeClient = mm.getAuthClientByID(data['data'])
  if removeClient == None:
    return
  if removeClient.user != ac.user and not mm.userInGroup(ac, "Admins"):
    mm.sendPopupError(ac.rawClient, "Error", "You are not authorised")
    return
  mm.unauth(removeClient)
  mm.sendPopupSuccess(ac.rawClient, "Success", "Client removed!")
  if(ac.currentPage == "/main/Admin" and mm.userInGroup(ac, "Admins")):
    loadSessionsAdmin(ac)
  else:
    loadSessions(ac)



def loadSessions(ac):
  obj = []
  for client in mm.authServer.clients:
    if client.user != ac.user:
      continue
    obj.append({
      'username': client.username,
      'address': client.rawClient.address,
      'currentPage': client.currentPage,
      'clientid': client.rawClient.clientid,
      'timeout': client.timeout
    })
    # obj.append(client.session)
  ac.send('sessions', obj)



def changePassword(ac, data): 
  # If the account is not an admin, and the username is the same, and the password is correct => Change password
  # If the account is not an admin, and the username is the same, and the password not correct and => Incorrect Password
  # If the account is not an admin, and the username is not the same => Access denied
  # If the account is an admin, and the username is the same, and the password is correct => Change password
  # If the account is an admin, and the username is the same, and the password is not correct => Incorrect Password
  # If the account is an admin, and the username is not the same => Change password

  isAdmin = mm.userInGroup(ac, 'Admins')
  correctName = ac.user.id == data['data']['id']
  
  
  if isAdmin and correctName and not 'old' in data['data']:
    mm.sendPopupError(ac.rawClient, "Error", "You are not authorised")
    return
  
  
  if isAdmin or correctName:
    if not isAdmin and ac.user.sha256passwordhash != data['data']['old']:
      mm.sendPopupError(ac.rawClient, "Error", "Incorrect Password")
      return
    elif isAdmin and correctName and ac.user.sha256passwordhash != data['data']['old']:
      mm.sendPopupError(ac.rawClient, "Error", "Incorrect Password")
      return
  else:
    mm.sendPopupError(ac.rawClient, "Error", "You are not authorised")
    return
  
  user = mm.getUserById(data['data']['id'])
  if user == None:
    mm.sendPopupError(ac.rawClient, "Error", "Invalid id")
    return 
  
  mm.setUserPassword(user, data['data']['new'])
  mm.sendPopupSuccess(ac.rawClient, "Success", "Password updated!")
  
  if isAdmin:
    loadSessionsAdmin(ac)



def loadSessionsAdmin(ac):
  if not mm.userInGroup(ac, 'Admins'):
    return
  
  obj = {
    'users': [],
    'sessions': []
  }
  for client in mm.authServer.clients:
    obj['sessions'].append({
      'username': client.username,
      'address': client.rawClient.address,
      'currentPage': client.currentPage,
      'clientid': client.rawClient.clientid,
      'timeout': client.timeout
    })
  for user in mm.authServer.users:
    obj['users'].append({
      'username': user.username,
      'permGroups': user.permGroups,
      'id': user.id,
      'created': user.created,
      'passwordUpdated': user.passwordUpdated
    })
  ac.send('sessions', obj)



def addUser(ac, data):
  if not mm.userInGroup(ac, 'Admins'):
    mm.sendPopupError(ac.rawClient, "Error", "You are not authorised")
    return
  
  mm.addUser(
    data['data']['username'],
    data['data']['groups'],
    data['data']['password'])
  loadSessionsAdmin(ac)



def disconnectAllSessions(ac, data):
  if not mm.userInGroup(ac, 'Admins'):
    mm.sendPopupError(ac.rawClient, "Error", "You are not authorised")
    return
  
  user = mm.getUserById(data['data']['id'])
  
  for client in mm.authServer.clients:
    if client.user == user:
      mm.unauth(client)
  loadSessionsAdmin(ac)



def changeGroups(ac, data):
  if not mm.userInGroup(ac, 'Admins'):
    mm.sendPopupError(ac.rawClient, "Error", "You are not authorised")
    return
  
  user = mm.getUserById(data['data']['id'])
  if user == None:
    mm.sendPopupError(ac.rawClient, "Error", "Invalid id")
    return
  if user == ac.user:
    mm.sendPopupError(ac.rawClient, "Error", "You are not authorised")
    return
  
  mm.setUserGroups(user, data['data']['groups'])
  mm.sendPopupSuccess(ac.rawClient, "Success", "Groups updated!")  
  loadSessionsAdmin(ac)



def deleteUser(ac, data):
  if not mm.userInGroup(ac, 'Admins'):
    mm.sendPopupError(ac.rawClient, "Error", "You are not authorised")
    return
  
  user = mm.getUserById(data['data']['id'])
  if user == None:
    mm.sendPopupError(ac.rawClient, "Error", "Invalid id")
    return
  if user == ac.user:
    mm.sendPopupError(ac.rawClient, "Error", "You are not authorised")
    return
  
  mm.deleteUser(user)
  mm.sendPopupSuccess(ac.rawClient, "Success", "User deleted!")  
  loadSessionsAdmin(ac)