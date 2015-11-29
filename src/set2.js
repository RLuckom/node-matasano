'use strict';
const crypto = require('crypto');
const _ = require('lodash');

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

function aesUpTo1024ECB_CBC_Detector(f) {
  let testBuf = new Buffer(600);
  testBuf.fill(67);
  let encrypted = f(testBuf);
  let bestScore = 0;
  let bestKeyLength = null;
  for (let keyLength = 8; keyLength <= 128; keyLength = keyLength * 2) { 
    let seen = {};
    for (let pos = 0; pos < encrypted.length; pos += keyLength) {
      let cur = encrypted.slice(pos, pos + keyLength).toString('base64');
      seen[cur] = seen[cur] ? seen[cur] + 1 : 1;
    }
    if (_.max(seen) > 1) {
      let score = _.max(seen) / (encrypted.length / keyLength);
      if (score > bestScore) {
        bestScore = score;
        bestKeyLength = keyLength;
      }
    }
  }
  if (bestKeyLength) {
    return {name: 'aes-' + bestKeyLength * 8 + '-ecb', keyLength: bestKeyLength};
  }
  return 'cbc';
}

function byteWiseDecryptECB(f) {
  let alg = aesUpTo1024ECB_CBC_Detector(f);
  if (alg.name === 'cbc') {
    throw new Error('cannot decrypt cbc mode ciphertext');
  }
  function findNextByte(knownBytes) {
    let testBufLength = knownBytes.length + 1;
    let paddingBuf = new Buffer(alg.keyLength - (testBufLength % alg.keyLength));
    paddingBuf.fill(0);
    let testBuf = new Buffer(testBufLength);
    knownBytes.copy(testBuf);
    let bytesMap = {};
    let controlledBytesLength = testBufLength + paddingBuf.length;
    for (let val =0; val < 256; val++) {
      testBuf[knownBytes.length] = val;
      bytesMap[f(Buffer.concat([paddingBuf, testBuf])).slice(0, controlledBytesLength).toString('base64')] = val;
    }
    return bytesMap[f(paddingBuf).slice(0, controlledBytesLength).toString('base64')];
  }
  let cipherTextLength = f(new Buffer(0)).length;
  let clearText = new Buffer(cipherTextLength);
  for (let indx = 0; indx < cipherTextLength; indx++) {
    clearText[indx] = findNextByte(clearText.slice(0, indx));
  }
  return clearText;
}


module.exports = {
  aes128ECBCipher: aes128ECBCipher,
  aes128ECBDecipher: aes128ECBDecipher,
  aes128CBCCipher: aes128CBCCipher,
  aesUpTo1024ECB_CBC_Detector: aesUpTo1024ECB_CBC_Detector,
  aes128CBCDecipher: aes128CBCDecipher,
  padBuffer: padBuffer,
  xorBufs: xorBufs,
  byteWiseDecryptECB: byteWiseDecryptECB
};
