const _ = require('lodash');
const crypto = require('crypto');

export function hexToB64(hexString) {
  return new Buffer(hexString, 'hex').toString('base64');
}

export function xorHex(hexString1, hexString2) {
  let b1 = new Buffer(hexString1, 'hex');
  let b2 = new Buffer(hexString2, 'hex');
  let xored = new Buffer(b1.length);
  for(let x = 0; x < b1.length; x++) {
    xored[x] = b1[x] ^ b2[x];
  }
  return xored.toString('hex');
}

// lowest is best. Good texts are around 1.6 usually
export function isEnglishScore(s) {
  let lower = s.toLowerCase();
  return _.sum(characterFrequencies, (expectedPct, letter) => {
    return Math.abs(expectedPct - (countOccurrences(lower, letter) / s.length));
  });
}

export function countOccurrences(s, sub) {
  return (s.match(new RegExp(sub, 'g')) || []).length;
}

export function repeatedXor(buf, xorBuf) {
  let xored = new Buffer(buf.length);
  for(let x = 0; x < buf.length; x++) {
    xored[x] = buf[x] ^ xorBuf[x % xorBuf.length];
  }
  return xored;
}

export function hammingDistance(buf1, buf2) {
  let longestLen = _.max([buf1.length, buf2.length]);
  let dist = 0;
  for (let x = 0; x < longestLen; x++) {
    for (let pos = 0; pos < 16; pos++) {
      let mask = 1 << pos;
      dist += (buf1[x] & mask) === (buf2[x] & mask) ? 0 : 1;
    }
  }
  return dist;
}

export function testKeySize(buf, size) {
  let b1 = new Buffer(buf.slice(0, size));
  let b2 = new Buffer(buf.slice(size, size * 2));
  let b3 = new Buffer(buf.slice(size * 2, size * 3));
  let b4 = new Buffer(buf.slice(size * 3, size * 4));
  let d1 = hammingDistance(b1, b2) / size;
  let d2 = hammingDistance(b1, b3) / size;
  let d3 = hammingDistance(b1, b4) / size;
  let d4 = hammingDistance(b2, b3) / size;
  let d5 = hammingDistance(b2, b4) / size;
  let d6 = hammingDistance(b3, b4) / size;
  return _.sum([d1, d2, d3, d4, d5, d6]) / 6;
}

export function findKeySize(buf) {
  let keysize = null;
  for (let x = 1; x < 40; x++) {
    let currentScore = testKeySize(buf, x);
    keysize = !keysize || currentScore < keysize.score ? {score: currentScore, keysize: x} : keysize;
  }
  return keysize.keysize;
}

export function keyWithBestEnglishScore(buf, keyBufs) {
  let bestKeyBuf = null;
  _.each(keyBufs, (kb) => {
    let score = isEnglishScore(repeatedXor(buf, kb).toString('utf8'));
    bestKeyBuf = !bestKeyBuf || score < bestKeyBuf.score ? {score: score, keyBuf: kb} : bestKeyBuf;
  });
  return bestKeyBuf.keyBuf;
}

export function findKey(buf) {
  let keySize = findKeySize(buf);
  let key = new Buffer(keySize);
  let chars = [];
  for (let c = 0; c < 256; c++) {
    chars.push(new Buffer(1));
    chars[chars.length - 1][0] = c;
  }
  for (let x = 0; x < keySize; x++) {
    let buf1 = new Buffer(_.round(buf.length / keySize));
    for (let pos = 0; pos < _.round(buf.length / keySize); pos++) {
      buf1[pos] = buf[(pos * keySize) + x];
    }
    key[x] = keyWithBestEnglishScore(buf1, chars)[0];
  }
  return key;
}

// TODO: Why is the zero-length buffer necessary?
//
// Providing no buffer and calling crypto.createDecipher('aes-128-ecb', key)
// produces garbage output for the ciphertext provided in the challenge, but 
// works fine to decipher a ciphertext encrypted with 
// crypto.createCipher('aes-128-ecb', key).
//
// I might chalk it up to an implementation quirk if not for the fact that I
// also can't decipher the given ciphertext using the OpenSSL CLI, and the
// command I tried:
//
// openssl aes-128-ecb -d -a -nopad -nosalt -k "YELLOW SUBMARINE" < test/7.txt
//
// produces output visually identical to the output produced by
// 
// crypto.createDecipher('aes-128-ecb', key)
//
// So I have two questions:
//
// 1) What is the correct openssl invocation to decipher the ciphertext?
// 2) What is the difference between providing a zero-length IV buffer and
//    whatever the default is?
export function aes128ECBDecipher(s, key) {
  let decipher = crypto.createDecipheriv('aes-128-ecb', key, new Buffer(0));
  let b = new Buffer(s, 'base64');
  let plaintext = Buffer.concat([decipher.update(b),  decipher.final()]);
  return plaintext;
}

export function isAES128ECB(buf) {
  let known = [];
  let blockSize = 16;
  for(let pos = 0; pos < buf.length; pos += blockSize) {
    let cur = buf.slice(pos, pos + blockSize).toString('base64');
    if (known.indexOf(cur) !== -1) {
      return true;
    }
    known.push(cur);
  }
  return false;
}


// from the project gutenberg text of Moby Dick, because I an a ridiculous
// fashion victim
const characterFrequencies = {
  "0": 0.00012725742745928954,
  "1": 0.0001598671432457325,
  "2": 0.00006203799588640366,
  "3": 0.00004772153529723358,
  "4": 0.000038972587159407424,
  "5": 0.0000532890477485775,
  "6": 0.00003499579255130463,
  "7": 0.00005090297098371582,
  "8": 0.00005487976559181862,
  "9": 0.00003738186931616631,
  "T": 0.002043277069643218,
  "h": 0.049270099117628814,
  "e": 0.09353898133610755,
  " ": 0.15698317179593635,
  "P": 0.0009210256312366081,
  "r": 0.04171418936223349,
  "o": 0.055395158173028744,
  "j": 0.0007277534132828121,
  "c": 0.01744778866359022,
  "t": 0.06918031900255628,
  "G": 0.0005973145501370404,
  "u": 0.021421401836006534,
  "n": 0.0520395388827116,
  "b": 0.012486339710521167,
  "g": 0.016295313586162027,
  "E": 0.0010824834923255817,
  "B": 0.0011659961790957405,
  "k": 0.006371620321102304,
  "f": 0.016196689079881078,
  "M": 0.0006219706767072777,
  "y": 0.013401002470384811,
  "D": 0.0006378778551396889,
  "i": 0.05006307196248451,
  ";": 0.003323804933452319,
  "W": 0.001054645930068862,
  "a": 0.06063339203082175,
  "l": 0.03367470138249288,
  ",": 0.015415646618849688,
  "H": 0.001190652305665978,
  "m": 0.01819224461422706,
  "v": 0.0067923651906395795,
  "\r": 0.017583795039187333,
  "\n": 0.017583795039187333,
  "s": 0.04989684194786581,
  "w": 0.01684092980639373,
  "d": 0.03019739217716779,
  ".": 0.006293675146783489,
  "Y": 0.0002863292117834015,
  "p": 0.013165576229585125,
  "-": 0.004820670423942212,
  "L": 0.0007627492058341167,
  ":": 0.00017418360383490258,
  "A": 0.0021673530614160254,
  "U": 0.00022588193374023895,
  "J": 0.0002075886785429661,
  "#": 7.953589216205597e-7,
  "R": 0.000711846234850401,
  "S": 0.0018110322645300144,
  "O": 0.0008351268677015877,
  "F": 0.0006871901082801635,
  "I": 0.002895901833620458,
  "C": 0.0009425003221203632,
  "N": 0.0009870404217311147,
  "K": 0.00014714140049980353,
  "z": 0.00047562463512909473,
  "'": 0.002333583076034722,
  "x": 0.0008247872017205204,
  "V": 0.0001439599648133213,
  "q": 0.0009894264984959763,
  "\"": 0.002478338399769664,
  "X": 0.000019883973040513993,
  "!": 0.0014061945734251495,
  "Q": 0.0002569009316834408,
  "Z": 0.000030223639021581268,
  "_": 0.000003181435686482239,
  "$": 0.000003181435686482239,
  "&": 0.0000015907178432411195,
  "/": 0.000020679331962134552,
  "%": 7.953589216205597e-7,
  "@": 0.0000015907178432411195
};
