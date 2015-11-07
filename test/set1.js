const set1 = require('../src/set1.js');
const expect = require('chai').expect;
const fs = require('fs');
const _ = require('lodash');

describe('set1 functions', () => {
  describe('Challenge 1: hex to b64', () => {
    it('converts correctly', () => {
      const testString = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d';
      const expectedString = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t';
      expect(set1.hexToB64(testString)).to.equal(expectedString);
    });
  });
  describe('Challenge 2: xor hex', () => {
    it('converts correctly', () => {
      let s1 = '1c0111001f010100061a024b53535009181c';
      let s2 = '686974207468652062756c6c277320657965';
      let expected = '746865206b696420646f6e277420706c6179';
      expect(set1.repeatedXor(new Buffer(s1, 'hex'), new Buffer(s2, 'hex')).toString('hex')).to.equal(expected);
    });
  });
  describe('Challenge 3: Single-byte XOR', () => {
    describe('set1.countOccurrences', () => {
      it('converts correctly', () => {
        expect(set1.countOccurrences('hhh', 'h')).to.equal(3);
        expect(set1.countOccurrences('hhh', '5')).to.equal(0);
      });
    });
    // Get a map of english character frequencies.
    // To use: download the project gutenberg text of moby dick, replace
    // filenames here if needed. Manually remove chars that make regexes barf;
    // it's good enough for now without them.
    xdescribe('textanalyze moby dick', () => {
      it('has words', () => {
        let mobyDick = fs.readFileSync('./pg2701.txt', {encoding: 'utf8'});
        let hist = {};
        _.each(mobyDick, (ch) => {
          hist[ch] = hist[ch] ? hist[ch] + 1 : 1;
        });
        fs.writeFileSync('hist.json', JSON.stringify(_.mapValues(hist, (v) => {return v / mobyDick.length;}), null, 2));
      });
    });
    describe('dial in set1.isEnglishScore', () => {
      it('log the scores here to see how set1.isEnglishScore does', () => {
        set1.isEnglishScore('kjhfzdxcvbkjtrsdxcnvkjtrdcvgjfxcfrdsfx');
        set1.isEnglishScore('hello, this is an english sentence');
        set1.isEnglishScore('to be ornot to be that is the question whether tis nobler in the mind to suffer the slings and arrows');
      });
    });
    describe('find plaintext', () => {
      it('figures out what byte the plaintext was XORed with and reverses the XOR', () => {
        let best = null;
        let secret = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736';
        let secretBuf = new Buffer(secret, 'hex');
        let xor = new Buffer(1);
        for(let v = 0; v < 256; v++) {
          xor[0] = v;
          let current = set1.repeatedXor(secretBuf, xor).toString('utf8');
          let currentScore = set1.isEnglishScore(current);
          best = !best || currentScore < best.score ? {string: current, score: currentScore} : best;
        }
        console.log(best);
      });
    });
  });
  describe('Challenge 4: detect single-character XOR', () => {
    it('detects and deciphers a single-character XORed string', function() {
      this.timeout(5000);
      let secrets = fs.readFileSync('./handouts/4.txt', {encoding: 'utf8'}).split('\n');
      let best = null;
      let xor = new Buffer(1);
      _.each(secrets, (secret) => {
        for(let v = 0; v < 256; v++) {
          let secretBuf = new Buffer(secret, 'hex');
          xor[0] = v;
          let current = set1.repeatedXor(secretBuf, xor).toString('utf8');
          let currentScore = set1.isEnglishScore(current);
          best = !best || currentScore < best.score ? {string: current, score: currentScore} : best;
        }
      });
      console.log(best);
    });
  });
  describe('Challenge 5: Repeating xor', () => {
    function testRepeatingXOR(s, xor, expectedHex) {
      let buf = new Buffer(s, 'utf8');
      let xorBuf = new Buffer(xor, 'utf8');
      expect(set1.repeatedXor(buf, xorBuf).toString('hex')).to.equal(expectedHex);
    }
    it('xors to correct hex', () => {
      testRepeatingXOR(
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
        'ICE', 
        '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272' +
        'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
      );
    });
  });
  describe('Challenge 6: Break repeating-key XOR', () => {
    describe('set1.hammingDistance', () => {
      it('is calculated correctly', () => {
        expect(set1.hammingDistance(new Buffer('this is a test', 'utf8'), new Buffer('wokka wokka!!!', 'utf8'))).to.equal(37);
      });
    });
    describe('find the key, decrypt the message', () => {
      it('does those things', function() {
        this.timeout(5000);
        let secret = fs.readFileSync('./handouts/6.txt', {encoding: 'utf8'}).replace(/\n/g, '');
        let key = set1.findKey(new Buffer(secret, 'base64'));
        console.log('after setkey');
        let plain = set1.repeatedXor(new Buffer(secret, 'base64'), key).toString('utf8');
        console.log(plain);
      });
    });
  });
  describe('Challenge 7: decrypt aes-128-ecb when given the key', () => {
    it('decrypts correctly', function() {
      let secret = fs.readFileSync('./handouts/7.txt', {encoding: 'utf8'}).replace(/\n/g, '');
      let key = 'YELLOW SUBMARINE';
      console.log(set1.aes128ECBDecipher(secret, key).toString('utf8'));
    });
  });
  describe('Challenge 8: detect aes 128 ecb', () => {
    it('picks one line', function() {
      let secrets = fs.readFileSync('./handouts/8.txt', {encoding: 'utf8'}).split('\n');
      _.each(secrets, (secret) => {if (set1.isAES128ECB(new Buffer(secret, 'base64'))) {console.log(secret);}});  
    });
  });
});
