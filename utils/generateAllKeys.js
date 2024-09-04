const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

// Create keys directory if it doesn't exist
const keysDir = path.join(__dirname, "../keys");
if (!fs.existsSync(keysDir)) {
  fs.mkdirSync(keysDir, { recursive: true });
}

// AES key and IV
const AES_KEY = crypto.randomBytes(32).toString("base64");
const AES_IV = crypto.randomBytes(16).toString("base64");
fs.writeFileSync(path.join(keysDir, "aes_key.pem"), AES_KEY);
fs.writeFileSync(path.join(keysDir, "aes_iv.pem"), AES_IV);

// EC key pair
const ec = crypto.createECDH("secp256k1");
ec.generateKeys();
const EC_PUBLIC_KEY = ec.getPublicKey("base64");
const EC_PRIVATE_KEY = ec.getPrivateKey("base64");
fs.writeFileSync(path.join(keysDir, "ec_public_key.pem"), EC_PUBLIC_KEY);
fs.writeFileSync(path.join(keysDir, "ec_private_key.pem"), EC_PRIVATE_KEY);

// DH key pair
const dh = crypto.createDiffieHellman(2048);
dh.generateKeys();
const DH_PUBLIC_KEY = dh.getPublicKey("base64");
const DH_PRIVATE_KEY = dh.getPrivateKey("base64");
fs.writeFileSync(path.join(keysDir, "dh_public_key.pem"), DH_PUBLIC_KEY);
fs.writeFileSync(path.join(keysDir, "dh_private_key.pem"), DH_PRIVATE_KEY);

// Ed25519 key pair
const ed25519Keys = crypto.generateKeyPairSync('ed25519');
const ed25519PublicKey = ed25519Keys.publicKey.export({ type: 'spki', format: 'pem' });
const ed25519PrivateKey = ed25519Keys.privateKey.export({ type: 'pkcs8', format: 'pem' });
fs.writeFileSync(path.join(keysDir, "ed25519_public_key.pem"), ed25519PublicKey);
fs.writeFileSync(path.join(keysDir, "ed25519_private_key.pem"), ed25519PrivateKey);

// X25519 key pair
const x25519Keys = crypto.generateKeyPairSync('x25519');
const x25519PublicKey = x25519Keys.publicKey.export({ type: 'spki', format: 'pem' });
const x25519PrivateKey = x25519Keys.privateKey.export({ type: 'pkcs8', format: 'pem' });
fs.writeFileSync(path.join(keysDir, "x25519_public_key.pem"), x25519PublicKey);
fs.writeFileSync(path.join(keysDir, "x25519_private_key.pem"), x25519PrivateKey);

// RSA-PSS key pair
const rsaKeys = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
fs.writeFileSync(path.join(keysDir, "rsa_public_key.pem"), rsaKeys.publicKey);
fs.writeFileSync(path.join(keysDir, "rsa_private_key.pem"), rsaKeys.privateKey);

// RSA key pair with custom padding
const rsaOaepKeys = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
fs.writeFileSync(path.join(keysDir, "rsa_oaep_public_key.pem"), rsaOaepKeys.publicKey);
fs.writeFileSync(path.join(keysDir, "rsa_oaep_private_key.pem"), rsaOaepKeys.privateKey);

// RSA key pair with custom prime factor and public exponent
const rsaPssKeys = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  saltLength: 20,
});
fs.writeFileSync(path.join(keysDir, "rsa_pss_public_key.pem"), rsaPssKeys.publicKey);
fs.writeFileSync(path.join(keysDir, "rsa_pss_private_key.pem"), rsaPssKeys.privateKey);

// RSA key pair with custom public exponent
const rsaCustomExponentKeys = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicExponent: 0x11, // Typically 0x10001
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
fs.writeFileSync(path.join(keysDir, "rsa_custom_exponent_public_key.pem"), rsaCustomExponentKeys.publicKey);
fs.writeFileSync(path.join(keysDir, "rsa_custom_exponent_private_key.pem"), rsaCustomExponentKeys.privateKey);


//RSA key pair with custom padding
const rsaCustomPaddingKeys = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  padding: crypto.constants.RSA_PKCS1_PADDING,
});
fs.writeFileSync(path.join(keysDir, "rsa_custom_padding_public_key.pem"), rsaCustomPaddingKeys.publicKey);
fs.writeFileSync(path.join(keysDir, "rsa_custom_padding_private_key.pem"), rsaCustomPaddingKeys.privateKey);