import json
import importlib
import sys
import multiprocessing as mupr

import src.web as web
import src.utils as utils

class module():
  def __init__(self):
    self.name = None
    self.module = None
    self.proc = None
    self.rootdir = None
    self.tabs = []

  def add(self):
    spec = importlib.util.spec_from_file_location(self.name, utils.getRoot(self.entrypoint))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    self.module = module

  def init(self, moduleMaster):
    self.module.init(moduleMaster)
    self.proc = mupr.Process(target=self.module.main)

  def run(self):
    self.proc.start()

  def stop(self):
    self.proc.stop()



class moduleMaster():
  def __init__(self):
    self.modules = []

    self.webserv = None
    self.app = None
    self.rawServer = None
    self.authServer = None
    self.defaultPage = ""
    self.vars = {}

    # self.addRawEventListener('test1', test1)

  def addModules(self, webserv):
    self.webserv = webserv

    mdirs = utils.listSubdirs(utils.getRoot('modules/'))

    for mname in mdirs:
      mjson = json.loads(open(utils.getRoot(f'modules/{mname}/module.json')).read())
      m = module()
      m.name = mjson['name']
      m.entrypoint = mjson['entrypoint']
      
      for tab in mjson['tabs']:
        mtab = utils.getatribinarr(self.webserv.webtabs, 'name', tab['name'])

        if mtab == None:
          mtab = web.webtab()
          mtab.name = tab['name']
          m.tabs.append(mtab)

        def recursiveAdder(objs):
          tmpPages = []
          for obj in objs:
            if obj['type'] == 'folder':
              folder = web.webpagefolder()
              folder.name = obj['name']
              tmpTmpPages = recursiveAdder(obj['pages'])
              for tmpobj in tmpTmpPages:
                folder.pages.append(tmpobj)
              tmpPages.append(folder)
            else:
              mpage = web.webpage()
              mpage.name = obj['name']
              mpage.requiredPermGroup = obj['requiredPermGroup']
              mpage.location = obj['location']
              tmpPages.append(mpage)
          return tmpPages

        tmpPages = recursiveAdder(tab['pages'])

        for obj in tmpPages:
          mtab.pages.append(obj)

        mtab.defaultPage = tab['defaultPage']

        self.webserv.webtabs.append(mtab)

      m.add()
      self.modules.append(m)

    # for tab in webserv.webtabs:
    #   tab.compileHtml('User')

  def initModules(self, webserv):
    self.webserv = webserv
    self.app = webserv.app
    self.rawServer = webserv.rawServer
    self.authServer = webserv.authServer

    self.defaultPage = f'/{webserv.defaultTab}/{webserv.defaultPage}'

    for module in self.modules:
      module.init(self)

  def runModules(self):
    for module in self.modules:
      module.run()




  def reloadUsers(self):
    self.authServer.reloadUsers()

  def editUser(self, user, varname, value):
    path = utils.getRoot('data/')+'creds.json'
    logins = json.loads(utils.readFile(path))
    for userdata in logins:
      if userdata['username'] == user.username:
        userdata[varname] = value
    
    utils.writeFile(path, json.dumps(logins, sort_keys=True, indent=2))
  
  def setUserPassword(self, user, hash):
    for ac in self.authServer.clients:
      if ac.user == user:
        self.unauth(ac)
    self.editUser(user, 'sha256passwordhash', hash)
    self.editUser(user, 'passwordUpdated', utils.getUnixTime())
    self.authServer.reloadUsers()

  def setUserGroups(self, user, groups):
    for ac in self.authServer.clients:
      if ac.user == user:
        self.unauth(ac)
    self.editUser(user, 'permGroups', groups)
    self.authServer.reloadUsers()

  def addUser(self, user, groups, hash):
    path = utils.getRoot('data/')+'creds.json'
    time = utils.getUnixTime()
    logins = json.loads(utils.readFile(path))
    logins.append({
      'username': user,
      'permGroups': groups,
      'created': time,
      'id': utils.randID(16),
      'passwordUpdated': time,
      'sha256passwordhash': hash
    })
    utils.writeFile(path, json.dumps(logins, sort_keys=True, indent=2))
    self.authServer.reloadUsers()

  def deleteUser(self, user):
    path = utils.getRoot('data/')+'creds.json'
    time = utils.getUnixTime()
    logins = json.loads(utils.readFile(path))
    for login in logins:
      if login['id'] == user.id:
        logins.remove(login)
    utils.writeFile(path, json.dumps(logins, sort_keys=True, indent=2))
    self.authServer.reloadUsers()

  def userInGroup(self, ac, group):
    if not self.authServer.validAc(ac):
      return False
    if (group != "") and not (group in ac.user.permGroups):
      return  False
    return True
  

  
  def getUserByName(self, name):
    returnArr = []
    for user in self.authServer.users:
      if user.username == name:
        returnArr.append(user)
    return returnArr

  def getUserById(self, id):
    return utils.getatribinarr(self.authServer.users, 'id', id)





  def getRawClients(self):
    return self.rawServer.clients

  def getAuthClients(self):
    return self.authServer.clients

  def addRawEventListener(self, eventName, func):
    self.rawServer.eventListeners.append({
      'type': eventName,
      'func': func
    })
  
  def addAuthEventListener(self, eventName, func):
    def tmpfunc(c, data):
      if not c in self.rawServer.clients:
        return
      ac = utils.getatribinarr(self.authServer.clients, 'rawClient', c)
      if ac == None:
        return
      if not self.authServer.validAc(ac):
        return

      func(ac, data)

    self.rawServer.addEventListener(eventName, tmpfunc)

  def getRawClientByID(self, ID):
    return utils.getatribinarr(self.rawServer.clients, 'clientid', ID)

  def getAuthClientByID(self, ID):
    c = utils.getatribinarr(self.rawServer.clients, 'clientid', ID)
    if c == None:
      return None
    return utils.getatribinarr(self.authServer.clients, 'rawClient', c)

  def addPageEventListener(self, page, func):
    self.authServer.pageListeners.append({
      'page': page,
      'func': func
    })



  def getVar(self, varName):
    return self.vars[varname]

  def setVar(self, varName, val):
    self.vars[varName] = val


  def unauth(self, ac):
    ac.send('redir', {
      "location": "/"
    })
    self.authServer.unauth(ac)


  def sendPopupInfo(self, c, title, msg):
    c.send('popupInfo', {
      'title': title,
      'msg': msg
    })
  
  def sendPopupSuccess(self, c, title, msg):
    c.send('popupSuccess', {
      'title': title,
      'msg': msg
    })

  def sendPopupWarning(self, c, title, msg):
    c.send('popupWarning', {
      'title': title,
      'msg': msg
    })

  def sendPopupError(self, c, title, msg):
    c.send('popupError', {
      'title': title,
      'msg': msg
    })
  
  def sendPopupColor(self, c, title, msg, color, isDark):
    c.send('popupColor', {
      'title': title,
      'msg': msg,
      'color': color,
      'isDark': isDark
    })