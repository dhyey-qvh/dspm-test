// Intentionally insecure scan fixtures. Never use in an application.
const crypto = require('node:crypto');

function md5Password(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

function sha1Signature(payload) {
  return crypto.createHash('sha1').update(payload).digest('hex');
}

function encryptEcb(block) {
  const cipher = crypto.createCipheriv('aes-128-ecb', Buffer.from('0123456789abcdef'), null);
  return Buffer.concat([cipher.update(block), cipher.final()]);
}

function encryptFixedIv(block) {
  const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from('0123456789abcdef'), Buffer.alloc(16));
  return Buffer.concat([cipher.update(block), cipher.final()]);
}

function weakRsaKey() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
}

function weakPasswordDerivation(password) {
  return crypto.pbkdf2Sync(password, 'fixed-salt', 100, 32, 'sha1');
}

function predictableResetToken() {
  return Math.random().toString(36).slice(2);
}

module.exports = { md5Password, sha1Signature, encryptEcb, encryptFixedIv, weakRsaKey, weakPasswordDerivation, predictableResetToken };
