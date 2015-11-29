'use strict';
const set2 = require('../src/set2.js');
const expect = require('chai').expect;
const crypto = require('crypto');
const fs = require('fs');
const _ = require('lodash');

describe('Set 2: test padding', () => {
  describe('Challenge 9: test padding', () => {
    it('pads to a multiple of size', () => {
      let buffer = new Buffer('YELLOW SUBMARINE', 'utf8');
      expect(set2.padBuffer(buffer, 20).length).to.equal(20);
      expect(set2.padBuffer(buffer, 20).slice(0, 16).toString('utf8')).to.equal('YELLOW SUBMARINE');
      expect(set2.padBuffer(buffer, 20, 'g'.charCodeAt(0)).slice(16, 20).toString('utf8')).to.equal('gggg');
    });
  });
  describe('Challenge 10: CBC Mode', () => {

    it('can decrypt 16 bytes at a time', () => {
      let text = 'YELLOW SRBMARINEYELLOW SUBMARINE';
      let key = 'YELLOW SUBMARINE';
      let buf = new Buffer(text);
      let encrypted = set2.aes128ECBCipher(buf, key);
      expect(set2.aes128ECBDecipher(encrypted.slice(0, 16), key).toString('utf8')).to.equal('YELLOW SRBMARINE');
    });

    it('decrypts handout 10 correctly', () => {
      let ten = fs.readFileSync('./handouts/10.txt', {encoding: 'utf8'}).replace(/\n/g, '');
      let decrypted = set2.aes128CBCDecipher(new Buffer(ten, 'base64'), 'YELLOW SUBMARINE').toString('utf8');
      console.log(decrypted);
      let decryptedBuf = new Buffer(decrypted);
      expect(set2.aes128CBCCipher(decryptedBuf, 'YELLOW SUBMARINE').toString('base64')).to.equal(ten);
    });
  });

  describe('Challenge 11: ECB / CBC Detector', () => {
    function makeCheater() {
      var n = 0;
      return (buf) => {
        let key = crypto.randomBytes(16);
        let bytesToAppendBefore = crypto.randomBytes(Math.floor(Math.random() * 6) + 5);
        let bytesToAppendAfter = crypto.randomBytes(Math.floor(Math.random() * 6) + 5);
        if (n === 0) {
          n = 1;
          let padded = Buffer.concat([bytesToAppendBefore, buf, bytesToAppendAfter]);
          let encrypted = set2.aes128ECBCipher(padded, key);
          return encrypted;
        }
        n = 0;
        return set2.aes128CBCCipher(Buffer.concat([bytesToAppendBefore, buf, bytesToAppendAfter]), key, crypto.randomBytes(16));
      };
    }
    function honest(buf) {
      let n = Math.floor(Math.random() * 2);
      let key = crypto.randomBytes(16);
      let bytesToAppendBefore = crypto.randomBytes(Math.floor(Math.random() * 6) + 5);
      let bytesToAppendAfter = crypto.randomBytes(Math.floor(Math.random() * 6) + 5);
      if (n === 0) {
        let padded = Buffer.concat([bytesToAppendBefore, buf, bytesToAppendAfter]);
        let encrypted = set2.aes128ECBCipher(padded, key);
        return encrypted;
      }
      return set2.aes128CBCCipher(Buffer.concat([bytesToAppendBefore, buf, bytesToAppendAfter]), key, crypto.randomBytes(16));
    }

    it('detects ecb or cbc correctly in known cases', () => {
      let cheater = makeCheater();
      for (let n = 0; n < 100; n++) {
        if (n % 2 === 0) {
          let res = set2.aesUpTo1024ECB_CBC_Detector(cheater);
          expect(res.name).to.equal('aes-128-ecb');
          expect(res.keyLength).to.equal(16);
        } else {
          expect(set2.aesUpTo1024ECB_CBC_Detector(cheater)).to.equal('cbc');
        }
      }
    });
    it('detects ecb or cbc correctly in the conditions of the assignment', () => {
      for (let n = 0; n < 100; n++) {
        set2.aesUpTo1024ECB_CBC_Detector(honest); // I guess I just hope it's right?
      }
    });
  });
  describe('Challenge 12: decrypt ECB', () => {
    let b64Text = ('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\n' +
      'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\n' +
      'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\n' +
      'YnkK').replace(/\n/g, '');
    function makeCh12Function() {
      let key = crypto.randomBytes(16);
      let b64Buf = new Buffer(b64Text, 'base64');
      return (plainBuf) => {
        return set2.aes128ECBCipher(Buffer.concat([plainBuf, b64Buf]), key);
      };
    }

    it('detects the length of the key', () => {
      expect(set2.aesUpTo1024ECB_CBC_Detector(makeCh12Function()).keyLength).to.equal(16);
    });
    it('detects the encryption scheme', () => {
      expect(set2.aesUpTo1024ECB_CBC_Detector(makeCh12Function()).name).to.equal('aes-128-ecb');
    });
    it('decrypts the message byte by byte', () => {
      expect(set2.byteWiseDecryptECB(makeCh12Function()).slice(0, new Buffer(b64Text, 'base64').length).toString('base64')).to.equal(b64Text);
    });
  });
});
