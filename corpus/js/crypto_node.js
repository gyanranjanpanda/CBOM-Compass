const crypto = require('crypto');
const jwt = require('jsonwebtoken');

function weakFingerprint(data) {
  return crypto.createHash('md5').update(data).digest('hex');
}

function legacyFingerprint(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

function fingerprint(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function weakCipher(key, iv) {
  return crypto.createCipheriv('aes-128-cbc', key, iv);
}

function strongCipher(key, iv) {
  return crypto.createCipheriv('aes-256-gcm', key, iv);
}

function legacyCipher(key, iv) {
  return crypto.createCipheriv('des-ede3-cbc', key, iv);
}

function rsaKeys() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
}

function edKeys() {
  return crypto.generateKeyPairSync('ed25519');
}

function signRs(payload, key) {
  return jwt.sign(payload, key, { algorithm: 'RS256' });
}

function signEs(payload, key) {
  return jwt.sign(payload, key, { algorithm: 'ES256' });
}
