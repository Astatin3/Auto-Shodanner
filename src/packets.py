import os
import base64 
from hashlib import sha256
from flask import Flask, render_template, Response
from flask import request, redirect, url_for, make_response

import src.jsonpack as jsonpack
import src.utils as utils

import queue

class rawClient:
  def __init__(self, rawServer):
    self.clientid = utils.randID(32)
    self.messages = queue.Queue()
    self.rawServer = rawServer
    self.address = None
  def send(self, type, msg):
    self.rawServer.sendClient(self, jsonpack.pack({
      'type': type,
      'data': msg,
      'cid': self.clientid
    }))

#Credit to https://github.com/MaxHalford/flask-sse-no-deps
class rawServer:

  def __init__(self, webserv):
    self.eventListeners = []
    self.clients = []
    self.webserv = webserv
    self.app = webserv.app
    # self.app = app

  def listen(self):
    c = rawClient(self)
    self.clients.append(c)
    return self.clients[-1]

  def broadcast(self, msg):
    # We go in reverse order because we might have to delete an element, which will shift the
    # indices backward
    ssedata = format_sse(msg)
    for i in reversed(range(len(clients))):
      try:
        self.clients[i].messages.put_nowait(ssedata)
      except queue.Full:
        del self.clients[i]

  def sendClient(self, c, msg):
    if c not in self.clients:
      return
    ssedata = format_sse(msg)
    c.messages.put_nowait(ssedata)
  
  def clientByCID(self, cid):
    for c in self.clients:
      if c.clientid == cid:
        return c
    return None
  
  def addEventListener(self, eventName, func):
    self.eventListeners.append({
      'type': eventName,
      'func': func
    })

def format_sse(data: str, event=None) -> str:
  #Formats a string and an event name in order to follow the event stream convention.
  msg = f'data: {data}\n\n'
  if event is not None:
    msg = f'event: {event}\n{msg}'
  return msg


def startRawListener(webserv):
  server = rawServer(webserv)
  # app.rawServer = server

  @webserv.app.route('/listen', methods=['GET', 'POST'])
  def listen():

    if request.method == 'GET':

      c = server.listen()  # returns a queue.Queue
      c.address = request.remote_addr
      c.send('clidata', {
        'cid': c.clientid
      })

      def stream():
        while True:
          msg = c.messages.get()  # blocks until a new message arrives
          yield msg

      return Response(stream(), mimetype='text/event-stream')
    if request.method == 'POST':

      data = jsonpack.unpack(request.data.decode("utf-8"))

      if data['cid'] == None:
        return {}, 400
      c = utils.getatribinarr(server.clients, 'clientid', data['cid'])
      if c == None:
        return {}, 400
      
      for event in server.eventListeners:
        if event['type'] == data['type']:
          event['func'](c, data)

      return {}, 200

  return server