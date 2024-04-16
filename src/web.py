import os
import src.utils as utils
import multiprocessing as mupr

from flask import Flask, render_template, Response
from flask import request, redirect, url_for, make_response

import src.jsonpack as jsonpack
import src.packets as packets
import src.auth as auth

webroot = utils.getRoot('html/')

app = Flask(__name__,
  static_url_path=webroot,
  static_folder=webroot,
  template_folder=webroot)

class webtab():
  def __init__(self):
    self.name = None
    self.pages = []
    self.defaultPage = ''
    self.html = ''

  def compileHtml(self, permGroups):
    html = ''
    for page in self.pages:
      html += page.compileHtml(self.name, permGroups)
    return html

  def addPage(self, page):
    self.pages.append(page)
    
class webpagefolder():
  def __init__(self):
    self.name = None
    self.pages = []
  
  def compileHtml(self, tabname, permGroups):
    html = '<details><summary>' + self.name + '</summary><ul>'
    for page in self.pages:
      html += page.compileHtml(tabname, permGroups)
    html += '</ul></details>'
    return html

class webpage():
  def __init__(self):
    self.name = None
    self.requiredPermGroup = ''
    self.location = None
  
  def compileHtml(self, tabname, permGroups):
    html = '<li'
    if (self.requiredPermGroup == '') or (self.requiredPermGroup in permGroups):
      html += f' onclick=\'window.location="/{tabname}/{self.name}"\'>' +\
        self.name
    else:
      html += f'><del>{self.name}</del>'
    return html + '</li>'

@app.route('/')
def index():
  isValid = app.webserv.authServer.cookieLogin(request)
  if not isValid:
    return redirect("/login", code=302)
  else:
    return redirect(f'/{app.webserv.defaultTab}/{app.webserv.defaultPage}', code=302)

@app.route('/login')
def loginPage():
  isValid = app.webserv.authServer.cookieLogin(request)
  if isValid:
    return redirect(f'/{app.webserv.defaultTab}/{app.webserv.defaultPage}', code=302)

  return make_response(open(f'{webroot}nav.html', 'r').read()
    .replace('<!--Place body here!!!-->', open(f'{webroot}login.html', 'r').read())
    .replace('<!--Place tabs here!!!-->', '<a href="/login" role="button" class="outline topnav-button text-white">Login</a>')
    .replace('<!--Place title here!!!-->', app.webserv.title)
    .replace('<!--Place defaultPage here!!!-->', '/login'))

def recursivePageFinder(pagename, objs):
  returnVal = None
  for obj in objs:
    if isinstance(obj, webpagefolder):
      tmp = recursivePageFinder(pagename, obj.pages)
      if tmp != None:
        returnVal = tmp
    else:
      if obj.name == pagename:
        returnVal = obj
  return returnVal

@app.route('/<tabname>/<pagename>')
def page(tabname, pagename):
  
  isValid = app.webserv.authServer.cookieLogin(request)
  if not isValid:
    return redirect("/login", code=302)
  
  try:
  
    tab = utils.getatribinarr(app.webserv.webtabs, 'name', tabname)
    page = recursivePageFinder(pagename, tab.pages)

      # print(page.requiredPermGroup)

    isValid, permGroups = app.webserv.authServer.validPermGroup(page.requiredPermGroup, request)

    if not isValid:
      return redirect(f'/{tab.name}/{tab.defaultPage}', code=302)

    return make_response(open(utils.getRoot('html/nav.html'), 'r').read()
      .replace('<!--Place body here!!!-->', open(utils.getRoot(page.location), 'r').read())
      .replace('<!--Place tabs here!!!-->', app.webserv.tabHtml)
      .replace('<!--Place pages here!!!-->', tab.compileHtml(permGroups))
      .replace('<!--Place title here!!!-->', app.webserv.title)
      .replace('<!--Place defaultPage here!!!-->', f'/{app.webserv.defaultTab}/{app.webserv.defaultPage}'))
  except:
    return redirect("/", code=302)

@app.route('/src/<file>')
def src(file):
  return app.send_static_file(f'src/{file}')

@app.errorhandler(404)
def err404(err):
  return redirect("/", code=302)


class webserv():
  def __init__(self):
    self.title = 'Polyboard'
    self.port = 443
    self.host = '0.0.0.0'
    self.verbose = False
    self.secure = True
    self.tabHtml = ''
    self.webtabs = []
    self.defaultTab = 'main'
    self.defaultPage = ''

    self.app = None

  def init(self):
    if not self.verbose:
      import logging
      log = logging.getLogger('werkzeug')
      log.setLevel(logging.ERROR)

    if self.secure:
      dataroot = utils.getRoot("data/")
      sslcontext = (f'{dataroot}ssl.crt', f'{dataroot}ssl.key')
    else:
      sslcontext = None

    def tabHtml(path, name):
      return f'<a href="{path}" role="button" class="outline topnav-button text-white">{name}</a>'

    for tab in self.webtabs:
      if tab.name == self.defaultTab:
        self.tabHtml = tabHtml(f'/{tab.name}/{tab.defaultPage}', tab.name) + self.tabHtml
        self.defaultPage = tab.defaultPage
      else:
        self.tabHtml += tabHtml(f'/{tab.name}/{tab.defaultPage}', tab.name)

    app.webserv = self
    self.app = app
    self.rawServer = packets.startRawListener(self)
    self.authServer = auth.authServer(self)
    self.proc = mupr.Process(target=app.run, kwargs=dict(debug=self.verbose, port=self.port, host=self.host, ssl_context=sslcontext))


  def start(self):
    self.proc.start()
    
    # return self.rawServer

  def stop(self):
    self.proc.terminate()
  
  # def sendfatal(self, err):
  #   self.rawServer.broadcast(jsonpack.pack({
  #       'type': 'error',
  #       'severity': 'fatal',
  #       'error': err
  #     }))