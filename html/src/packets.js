import * as jsonpack from '/src/jsonpack.js'
import * as utils from "/src/utils.js"


let cID = null
let evListeners = []
let c = null

function getErrorDesc(error){
  switch(error){
    case 'invalidLogin':
      return 'Invalid username or password'
    case 'invalidLoginRequest':
      utils.setCookie('session', '')
      return 'Some part of the login request is invalid, please try again'
    case 'prelogin':
      window.location.pathname = '/'
      return 'You are already logged in'
  }
  return error
}

function processData(data){
  data = jsonpack.unpack(data)
  switch(data.type){
    case 'clidata':
      c.cID = data.data.cid
      if(window.location.pathname == "/login") {
        utils.popupWarning('Connection', 'Connected to server!')
        utils.iconunauth()
      }else{
        utils.popupInfo('Connection', 'Connected to server!')
        utils.iconauth()
      }
      break
    case 'redir':
      window.location.pathname = data.location
    case 'data':
      console.log(data.data)
      break
    case 'error':
      utils.popupError(`Error: ${data.data}`, getErrorDesc(data.data))
  }
  for(let i=0;i<evListeners.length;i++){
    const ev = evListeners[i]
    if(ev.type == data.type){
      ev.func(data)
    }
  }
}


export function rawClient(loc) {
  c = this
  this.connected = false
  this.location = loc
  this.evtSource = new EventSource(loc);

  this.onopen = ()=>{}
  this.onclose = ()=>{}

  this.cID = null

  this.evtSource.onmessage = (event) => {
    console.log(`Data: ${event.data}`)
    processData(event.data)
  }

  this.evtSource.onerror = (event) => {
    console.log('Error!')
    this.connected = false
    utils.icondisconnect()
    utils.popupError('Connection', 'Disconnected from server')
    this.onclose()
  }

  this.evtSource.onopen = (event) => {
    console.log('Connected!')
    this.connected = true
    utils.iconunauth()
    this.onopen()
  }

  this.send = (type, data)=>{
    //console.log({type, data})
    fetch(this.location, {
      method: "post",
      headers: {
        'Accept': '*',
        'Content-Type': 'text/plain'
      },
      body: jsonpack.pack({
        type: type,
        data: data,
        cid: this.cID
      })
    })
  }

  this.addRawTypeListener = (type, func)=>{
    evListeners.push({
      type: type,
      func: func
    })
  }
}