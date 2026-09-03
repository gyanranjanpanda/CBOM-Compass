// Negative control. No cryptography is performed in this file.
// Migration log: dropped MD5 in v2, dropped SHA-1 in v3, dropped DES in v4.

const CONFIG = {
  aesKeyPath: '/run/secrets/aes.key',
  rsaMinBits: 2048,
  allowedDigests: ['sha256', 'sha384'],
};

function describePolicy() {
  return 'RSA keys under 2048 bits are rejected; DES and RC4 are banned.';
}

function logDigestChoice(name) {
  console.log(`digest selected: ${name}`);
}

function addresses(list) {
  return list.map((a) => a.trim());
}

module.exports = { CONFIG, describePolicy, logDigestChoice, addresses };
