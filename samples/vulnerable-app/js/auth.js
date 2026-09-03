const crypto = require('crypto');
const jwt = require('jsonwebtoken');

function fingerprint(data) {
  return crypto.createHash('md5').update(data).digest('hex');
}

function sessionDigest(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function encryptCookie(key, iv) {
  return crypto.createCipheriv('aes-128-cbc', key, iv);
}

function issueToken(payload, privateKey) {
  return jwt.sign(payload, privateKey, { algorithm: 'RS256' });
}

function generateKeys() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
}
