"use strict";
const crypto = require('crypto');

function padBuffer(buffer, size, padByte) {
  // the padded size is exactly the buffer length if the buffer length is
  // already a multiple of size. Otherwise, the buffer length is size times one
  // more than buffer length / size, rounded down..
  let paddedSize = buffer.length % size === 0 ? buffer.length : size * (Math.floor(buffer.length / size) + 1);
  let newBuffer = new Buffer(paddedSize);
  padByte = padByte || 0;
  for (let n = 0; n < paddedSize; n++) {
    newBuffer[n] = n < buffer.length ? buffer[n] : padByte;
  }
  return newBuffer;
}

function aes128ECBDecipher(buf, key) {
  let padded = padBuffer(buf, 16);
  let decipher = crypto.createDecipheriv('aes-128-ecb', key, new Buffer(0));
  decipher.setAutoPadding(false);
  let plaintext = Buffer.concat([decipher.update(padded),  decipher.final()]);
  return plaintext;
}

function aes128ECBCipher(buf, key) {
  let padded = padBuffer(buf, 16);
  let cipher = crypto.createCipheriv('aes-128-ecb', key, new Buffer(0));
  cipher.setAutoPadding(false);
  let ciphertext = Buffer.concat([cipher.update(padded),  cipher.final()]);
  return ciphertext;
}

function xorBufs(b1, b2) {
  if (b1.length !== b2.length) {
    throw new Error('b1 was ' + b1.length + ', b2 was ${b2.length}');
  }
  let ret = new Buffer(b1.length);
  for (let pos = 0; pos < b1.length; pos++) {
    ret[pos] = b1[pos] ^ b2[pos];
  }
  return ret;
}

function aes128CBCDecipher(buf, key, iv) {
  if (!iv) {
    iv = new Buffer(16);
    iv.fill(0);
  }
  var last = new Buffer(16);
  iv.copy(last);
  let padded = padBuffer(buf, 16);
  let decrypted = new Buffer(padded.length);
  for (let pos = 0; pos < padded.length; pos += 16) {
    let current = padded.slice(pos, pos + 16);
    xorBufs(last, aes128ECBDecipher(current, key)).copy(decrypted, pos);
    last = current;
  }
  return decrypted;
}

function aes128CBCCipher(buf, key, iv) {
  if (!iv) {
    iv = new Buffer(16);
    iv.fill(0);
  }
  var last = new Buffer(16);
  iv.copy(last);
  let padded = padBuffer(buf, 16);
  let encrypted = new Buffer(padded.length);
  for (let pos = 0; pos < padded.length; pos += 16) {
    let current = padded.slice(pos, pos + 16);
    let currentCrypt = aes128ECBCipher(xorBufs(last, current), key);
    currentCrypt.copy(encrypted, pos);
    last = currentCrypt;
  }
  return encrypted;
}

function aes128ECB_CBC_Detector(f) {
  let testBuf = new Buffer(600);
  testBuf.fill(67);
  let encrypted = f(testBuf);
  let seen = [];
  for (let pos = 0; pos < encrypted.length; pos += 16) {
    let cur = encrypted.slice(pos, pos + 16).toString('base64');
    if (seen.indexOf(cur) !== -1) {
      return 'aes-128-ecb';
    }
    seen.push(cur);
  }
  return 'aes-128-cbc';
}

module.exports = {
  aes128ECBCipher: aes128ECBCipher,
  aes128ECBDecipher: aes128ECBDecipher,
  aes128CBCCipher: aes128CBCCipher,
  aes128ECB_CBC_Detector: aes128ECB_CBC_Detector,
  aes128CBCDecipher: aes128CBCDecipher,
  padBuffer: padBuffer,
  xorBufs: xorBufs
};
