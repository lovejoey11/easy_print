'use strict';

var base32 = require('../node_modules/thirty-two');
var unixtime = require('../node_modules/unixtime');
const dateTime = require('../node_modules/date-time');
var crypto = require('crypto');
var fs = require('fs');

var userid;
// var obj = JSON.parse(fs.readFile('data.json', 'utf-8', function(err, data) {
//   if (err) throw err;
//   console.log(data);
// }));
var user;
var user = JSON.parse(fs.readFileSync('data.json', 'utf8'));
// Async readFile
// fs.readFile('data.json', 'utf-8', function (err, data) {
//   if (err) throw err;
//   user = JSON.parse(data);
//   console.log(user);
// });
// console.log(user.key);
// Auto generate SecretKey
// const key = generateSecretASCII(20);
// const key = '12345678901234567890'
if (user.key === undefined || user.key === null || user.key ===''){
  var key = generateSecretASCII(20)
} else{
  var key = user.key;
}
console.log('Your Secret Key is: ' + user.secrete_key);
console.log('Please add it to your authenticator');
var SecretKey = {
  algorithm: 'sha1',
  ascii: key,
  hex: Buffer(key, 'ascii').toString('hex'),
  base32: base32.encode(Buffer(key)).toString().replace(/=/g, '')
}
// console.log(SecretKey);

// Get time stamp
var tstep = 30
  ,time = (Math.floor(unixtime()/tstep)).toString(16)
  ,offest = 0;
//padding time seed to 16 characters
while (time.length<16){
  time = '0'+ time;
}

var time_bytes_buff = new Buffer.from(hexstring2Bytes(time))
  , key_bytes_buff = new Buffer.from(hexstring2Bytes(SecretKey.hex));
function hexstring2Bytes(hexstring){
  var ret = []
    , temp;
  for (var i = 0; i < hexstring.length; i = i+2){
    temp = parseInt(hexstring[i]+hexstring[i+1],16);
    if ((temp & 0x80)>0){
      temp = temp - 0x100;
    }
    ret.push(temp);
  }
  return ret;
}

//encrypt process
var hash = crypto.createHmac(SecretKey.algorithm, key_bytes_buff)
      .update(time_bytes_buff).digest('hex');
// console.log("The encrypted hash code is: " + hash);
// console.log(hash.length);
var grpd_hash = [];
for (var i = 0; i < hash.length; i = i + 2){
  grpd_hash.push(hash[i]+hash[i+1]);}
// console.log(grpd_hash, "\n", grpd_hash.length);
offest = (new Buffer(grpd_hash[grpd_hash.length-1],'hex')[0]) & 0xf;
var binary = (((new Buffer(grpd_hash[offest],'hex')[0]) & 0x7f) << 24) |
             (((new Buffer(grpd_hash[offest + 1],'hex')[0]) & 0xff) << 16) |
             (((new Buffer(grpd_hash[offest + 2],'hex')[0]) & 0xff) << 8) |
             ((new Buffer(grpd_hash[offest + 3],'hex')[0]) & 0xff)
var opt = binary % 1000000;
var result = opt.toString();
while(result.length < 6){
  result = '0'+result;
}
// console.log(result);

//Save code to file
var content = {
  userid: 'demo',
  time: dateTime({local: true}),
  timestep: time,
  key: key,
  secrete_key: SecretKey.base32,
  pin: result
}
// var content = '{'
//             + '"Time" : '+ '\'' + dateTime({local: true})
//             + '"Base32 Secrete key" : ' + '"' + SecretKey.base32 + '"'
//             + '"Your code " : '+ '"' + result + '"';
//             '},' +'\n'
// TODO: use cipher insted to encrypt data
// content = base32.encode(content)
fs.writeFile('data.json', JSON.stringify(content, null, 2) +'\n', function (err) {
  if (err) throw err;
  console.log('File Updated!');
})

/**
 * Generates a random secret with the set A-Z a-z 0-9 and symbols, of any length
 * (default 32). Returns the secret key in ASCII, hexadecimal, and base32 format,
 * along with the URL used for the QR code for Google Authenticator (an otpauth
 * URL). Use a QR code library to generate a QR code based on the Google
 * Authenticator URL to obtain a QR code you can scan into the app.
 */
function generateSecretASCII (length, symbols) {
  var bytes = crypto.randomBytes(length || 32);
  var set = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz';
  if (symbols) {
    set += '!@#$%^&*()<>?/[]{},.:;';
  }

  var output = '';
  for (var i = 0, l = bytes.length; i < l; i++) {
    output += set[Math.floor(bytes[i] / 255.0 * (set.length - 1))];
  }
  return output;
};
