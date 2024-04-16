import * as utils from '/src/utils.js'
import * as jsonpack from '/src/jsonpack.js'

let c = null

export function authClient(rawClient) {
  c = this
  this.username = null
  this.permGroups = null
  this.accountCreated = null
  this.passwordUpdated = null
  this.id = null
  this.rawClient = rawClient

  this.login = (username, password)=>{
    const salt = utils.getUnixTime()
    const key = (utils.sha256(
      username +
      utils.sha256(password) +
      salt
    ))
    //console.log(c.rawClient.send)
    c.rawClient.send('login', {
      data: key,
      salt: salt
    })
  }

  this.clidata = (data)=>{
    const session = utils.getCookie('session')
    if(session != ''){
      this.rawClient.send('reauth', {
        session: session
      })
    }
  }

  this.loginSuccess = (data)=>{
    utils.popupSuccess('Connection', 'Successfully logged in!')
    utils.iconauth()
    console.log(data.data.session)
    if(data.data.session != null){
      utils.setCookie('session', data.data.session)
    }
    window.location = data.data.redir
  }

  this.reauth = (data)=>{

    this.username = data.data.username
    this.id = data.data.id
    this.permGroups = data.data.permGroups
    this.accountCreated = data.data.created
    this.passwordUpdated = data.data.passwordUpdated

    if(window.location.pathname == "/login"){
      utils.popupSuccess('Connection', 'Successfully logged in!')
    }
    utils.iconauth()
  }

  this.rawClient.addRawTypeListener('clidata', this.clidata)
  this.rawClient.addRawTypeListener('loginSuccess', this.loginSuccess)
  this.rawClient.addRawTypeListener('reauth', this.reauth)
}