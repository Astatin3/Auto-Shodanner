import * as utils from "/src/utils.js"
import * as packets from "/src/packets.js"
import * as auth from "/src/auth.js"
import * as jsonpack from "/src/jsonpack.js"

const hostname = window.location.href.split('/')[2]

//import * as crypto from "/src/crypto-js.min.js"

let client = new packets.rawClient('/listen')
let authClient = new auth.authClient(client)

window.utils = utils
window.packets = packets
window.auth = auth
window.jsonpack = jsonpack

window.client = client
window.authClient = authClient

window.authLogin = authClient.login
window.send = client.send
window.addListener = client.addRawTypeListener

window.addListener('popupInfo', (data)=>{
  window.utils.popupInfo(data.data.title, data.data.msg)
})

window.addListener('popupSuccess', (data)=>{
  window.utils.popupSuccess(data.data.title, data.data.msg)
})

window.addListener('popupWarning', (data)=>{
  window.utils.popupWarning(data.data.title, data.data.msg)
})

window.addListener('popupError', (data)=>{
  window.utils.popupError(data.data.title, data.data.msg)
})

window.addListener('popupColor', (data)=>{
  window.utils.addPopup(data.data.color, data.data.isDark, data.data.title, data.data.msg)
})

window.main()