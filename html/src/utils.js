export const getel = (id)=>{return document.getElementById(id)}

export const setCookie = (name, value, hours = 1, path = '/') => {
  const expires = new Date(Date.now() + hours * 6e4).toUTCString()
  document.cookie = `${name}=${encodeURIComponent(value)}; path=${path}; SameSite=None; secure=True; session=True`
}

export const getCookie = (name) => {
  return document.cookie.split('; ').reduce((r, v) => {
    const parts = v.split('=')
    return parts[0] === name ? decodeURIComponent(parts[1]) : r
  }, '')
}

export function genID(length = 8){
  // Declare all characters
  let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

  // Pick characers randomly
  let str = '';
  for (let i = 0; i < length; i++) {
      str += chars.charAt(Math.floor(Math.random() * chars.length));
  }

  return str;
}


export function icondisconnect() {
  let icon = document.getElementById('connecticon')
  icon.style.backgroundColor = "rgba(255, 0, 0, 0.2)"
  icon.style.borderColor = "#ff0000"
  icon.innerText = "Disconnected"
}

export function iconunauth() {
  let icon = document.getElementById('connecticon')
  icon.style.backgroundColor = "rgba(255, 255, 0, 0.2)"
  icon.style.borderColor = "#ffff00"
  icon.innerText = "Unauthenticated"
}

export function iconauth() {
  let icon = document.getElementById('connecticon')
  icon.style.backgroundColor = "rgba(0, 255, 0, 0.2)"
  icon.style.borderColor = "#00ff00"
  icon.innerText = "Authenticated"
}

// function addPopup(bgcolor, fgcolor, innerHTML) {
//   const elem = document.getElementById('popupBox')
//   const id = 'popup-'+genID(16)
//   elem.innerHTML = `<div class="popup"
//   class="popup"
//   style="background-color: ${bgcolor};
//   color: ${fgcolor}"
//   id='${id}'
//   onclick="elem=document.getElementById('${id}');elem.parentNode.removeChild(elem)">
//   ${innerHTML}
//   </div>` +
//   elem.innerHTML

//   setTimeout(()=>{
//     elem.parentNode.removeChild(elem)
//   }, 30000)

// }

export function getatribinarr(arr, atribname, value){
  for(let i=0;i<arr.length;i++){
    if(arr[i][atribname] == value){
      return arr[i]
    }
  }
  return null
}

export function modal(elem, bgcolor, header, textColor, title, innerHTML) {
  elem.innerHTML += `
  <dialog class="example ${textColor}" open>
    <article style="background-color:${bgcolor};">
      <header style="background-color:${header};">
        <p class='noselect ${textColor}' style='font-size:10px;opacity:0.75'>${formatTime(getUnixTime())}</p>
        <a class="close ${textColor}" onclick="this.parentElement.parentElement.parentElement.remove()"></a>
        ${title}
      </header>
      ${innerHTML}
    </article>
  </dialog>
  `
}

export function addPopup(bgcolor, isDark, title, content) {
  const elem = document.getElementById('popupBox')
  let header
  let textColor
  if(isDark){
    header = 'rgba(255,255,255,0.05)'
    textColor = "text-invert"
  }else{
    header = 'rgba(0,0,0,0.2)'
    textColor = ""
  }
  modal(elem, bgcolor, header, textColor, title, `<p class='${textColor}'>${content}</p>`)

}

export function popupInfo(title, text){
  addPopup('var(--card-sectionning-background-color)', true, title, text)
}

export function popupSuccess(title, text){
  addPopup('#005000', true, title, text)
}

export function popupWarning(title, text){
  addPopup('#393900', true, title, text)
}

export function popupError(title, text){
  addPopup('#500000', true, title, text)
}

export function confirmBox(bgcolor, isDark, title, yesFunc, noFunc) {
  const elem = document.body
  let header
  let textColor
  if(isDark){
    header = 'rgba(255,255,255,0.05)'
    textColor = "text-invert"
  }else{
    header = 'rgba(0,0,0,0.2)'
    textColor = ""
  }
  modal(elem, bgcolor,  header, textColor, title, `
  <button class="outline half-left" onclick="${yesFunc};document.body.removeChild(this.parentElement.parentElement)">Yes</button>
  <button class="half-right" onclick="${noFunc};document.body.removeChild(this.parentElement.parentElement)">No</button>`)
}

export function getUnixTime() {
  return (+ new Date())
}

export function formatTime(Millis){
  const date = new Date(Millis)
  
  if(date.getDate() != (new Date()).getDate()){
    return date.getMonth()+1 + "/" + date.getDate() + "/" + date.getFullYear()
  }else{
    var Hour = ""
    var Minute = ""
    var AmPm = ""

    if(date.getHours() == 0){
      Hour = "12"
      AmPm = "AM"
    }else if(date.getHours() < 12){
      Hour = date.getHours()
      AmPm = "AM"
    }else if(date.getHours() == 12){
      Hour = "12"
      AmPm = "PM"
    }else{
      Hour = date.getHours() - 12
      AmPm = "PM"
    }

    if(date.getMinutes() < 10){
      Minute = "0" + date.getMinutes()
    }else{
      Minute = date.getMinutes()
    }

    return Hour + ":" + Minute + " " + AmPm

  }
}

export function sha256(ascii) {
  function rightRotate(value, amount) {
      return (value>>>amount) | (value<<(32 - amount));
  };
  
  var mathPow = Math.pow;
  var maxWord = mathPow(2, 32);
  var lengthProperty = 'length'
  var i, j; // Used as a counter across the whole file
  var result = ''

  var words = [];
  var asciiBitLength = ascii[lengthProperty]*8;
  
  //* caching results is optional - remove/add slash from front of this line to toggle
  // Initial hash value: first 32 bits of the fractional parts of the square roots of the first 8 primes
  // (we actually calculate the first 64, but extra values are just ignored)
  var hash = sha256.h = sha256.h || [];
  // Round constants: first 32 bits of the fractional parts of the cube roots of the first 64 primes
  var k = sha256.k = sha256.k || [];
  var primeCounter = k[lengthProperty];
  /*/
  var hash = [], k = [];
  var primeCounter = 0;
  //*/

  var isComposite = {};
  for (var candidate = 2; primeCounter < 64; candidate++) {
      if (!isComposite[candidate]) {
          for (i = 0; i < 313; i += candidate) {
              isComposite[i] = candidate;
          }
          hash[primeCounter] = (mathPow(candidate, .5)*maxWord)|0;
          k[primeCounter++] = (mathPow(candidate, 1/3)*maxWord)|0;
      }
  }
  
  ascii += '\x80' // Append Ƈ' bit (plus zero padding)
  while (ascii[lengthProperty]%64 - 56) ascii += '\x00' // More zero padding
  for (i = 0; i < ascii[lengthProperty]; i++) {
      j = ascii.charCodeAt(i);
      if (j>>8) return; // ASCII check: only accept characters in range 0-255
      words[i>>2] |= j << ((3 - i)%4)*8;
  }
  words[words[lengthProperty]] = ((asciiBitLength/maxWord)|0);
  words[words[lengthProperty]] = (asciiBitLength)
  
  // process each chunk
  for (j = 0; j < words[lengthProperty];) {
      var w = words.slice(j, j += 16); // The message is expanded into 64 words as part of the iteration
      var oldHash = hash;
      // This is now the undefinedworking hash", often labelled as variables a...g
      // (we have to truncate as well, otherwise extra entries at the end accumulate
      hash = hash.slice(0, 8);
      
      for (i = 0; i < 64; i++) {
          var i2 = i + j;
          // Expand the message into 64 words
          // Used below if 
          var w15 = w[i - 15], w2 = w[i - 2];

          // Iterate
          var a = hash[0], e = hash[4];
          var temp1 = hash[7]
              + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) // S1
              + ((e&hash[5])^((~e)&hash[6])) // ch
              + k[i]
              // Expand the message schedule if needed
              + (w[i] = (i < 16) ? w[i] : (
                      w[i - 16]
                      + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15>>>3)) // s0
                      + w[i - 7]
                      + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2>>>10)) // s1
                  )|0
              );
          // This is only used once, so *could* be moved below, but it only saves 4 bytes and makes things unreadble
          var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) // S0
              + ((a&hash[1])^(a&hash[2])^(hash[1]&hash[2])); // maj
          
          hash = [(temp1 + temp2)|0].concat(hash); // We don't bother trimming off the extra ones, they're harmless as long as we're truncating when we do the slice()
          hash[4] = (hash[4] + temp1)|0;
      }
      
      for (i = 0; i < 8; i++) {
          hash[i] = (hash[i] + oldHash[i])|0;
      }
  }
  
  for (i = 0; i < 8; i++) {
      for (j = 3; j + 1; j--) {
          var b = (hash[i]>>(j*8))&255;
          result += ((b < 16) ? 0 : '') + b.toString(16);
      }
  }
  return result.toUpperCase();
};
