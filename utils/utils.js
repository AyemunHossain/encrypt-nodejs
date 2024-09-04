// crypto-utils.js

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

// Utility function to read a key from a file
const readKey = (keyPath) => {
  return fs.readFileSync(path.join(__dirname, keyPath));
};

// AES key and IV
const AES_KEY = readKey("../keys/aes_key.pem");
const AES_IV = readKey("../keys/aes_iv.pem");

// RSA keys
const rsaPublicKey = readKey("../keys/rsa_public_key.pem");
const rsaPrivateKey = readKey("../keys/rsa_private_key.pem");

// RSA OAEP keys
const rsaOaepPublicKey = readKey("../keys/rsa_oaep_public_key.pem");
const rsaOaepPrivateKey = readKey("../keys/rsa_oaep_private_key.pem");

// RSA PSS keys
const rsaPssPublicKey = readKey("../keys/rsa_pss_public_key.pem");
const rsaPssPrivateKey = readKey("../keys/rsa_pss_private_key.pem");

// RSA custom padding keys
const rsaCustomPaddingPublicKey = readKey("../keys/rsa_custom_padding_public_key.pem");
const rsaCustomPaddingPrivateKey = readKey("../keys/rsa_custom_padding_private_key.pem");

// RSA custom exponent keys
const rsaCustomExponentPublicKey = readKey("../keys/rsa_custom_exponent_public_key.pem");
const rsaCustomExponentPrivateKey = readKey("../keys/rsa_custom_exponent_private_key.pem");

// EC keys
const EC_PUBLIC_KEY = readKey("../keys/ec_public_key.pem");
const EC_PRIVATE_KEY = readKey("../keys/ec_private_key.pem");

// DH keys
const DH_PUBLIC_KEY = readKey("../keys/dh_public_key.pem");
const DH_PRIVATE_KEY = readKey("../keys/dh_private_key.pem");

// Ed25519 keys
const ed25519PublicKey = readKey("../keys/ed25519_public_key.pem");
const ed25519PrivateKey = readKey("../keys/ed25519_private_key.pem");

// X25519 keys
const x25519PublicKey = readKey("../keys/x25519_public_key.pem");
const x25519PrivateKey = readKey("../keys/x25519_private_key.pem");

// Common encryption/decryption functions
const encryptData = (data, publicKey, padding, oaepHash = "sha256") => {
  try {
    const encryptedData = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: padding,
        oaepHash: oaepHash,
      },
      Buffer.from(data)
    );
    return encryptedData.toString("base64");
  } catch (err) {
    console.error('Encryption Error:', err);
    return false;
  }
};

const decryptData = (data, privateKey, padding, oaepHash = "sha256") => {
  try {
    const decryptedData = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: padding,
        oaepHash: oaepHash,
      },
      Buffer.from(data, "base64")
    );
    return decryptedData.toString();
  } catch (err) {
    console.error('Decryption Error:', err);
    return false;
  }
};

// Specific encryption/decryption functions
const encrypt_RSA = (data) => encryptData(data, rsaPublicKey, crypto.constants.RSA_PKCS1_OAEP_PADDING);
const decrypt_RSA = (data) => decryptData(data, rsaPrivateKey, crypto.constants.RSA_PKCS1_OAEP_PADDING);

const encrypt_RSA_OAEP = (data) => encryptData(data, rsaOaepPublicKey, crypto.constants.RSA_PKCS1_OAEP_PADDING);
const decrypt_RSA_OAEP = (data) => decryptData(data, rsaOaepPrivateKey, crypto.constants.RSA_PKCS1_OAEP_PADDING);

const encrypt_RSA_PSS = (data) => encryptData(data, rsaPssPublicKey, crypto.constants.RSA_PKCS1_PSS_PADDING);
const decrypt_RSA_PSS = (data) => decryptData(data, rsaPssPrivateKey, crypto.constants.RSA_PKCS1_PSS_PADDING);

const encrypt_RSA_CustomPadding = (data) => encryptData(data, rsaCustomPaddingPublicKey, crypto.constants.RSA_NO_PADDING);
const decrypt_RSA_CustomPadding = (data) => decryptData(data, rsaCustomPaddingPrivateKey, crypto.constants.RSA_NO_PADDING);

const encrypt_RSA_CustomExponent = (data) => encryptData(data, rsaCustomExponentPublicKey, crypto.constants.RSA_PKCS1_OAEP_PADDING);
const decrypt_RSA_CustomExponent = (data) => decryptData(data, rsaCustomExponentPrivateKey, crypto.constants.RSA_PKCS1_OAEP_PADDING);

const encrypt_AES = (data) => {
  try {
    const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, AES_IV);
    let encrypted = cipher.update(data, "utf8", "base64");
    encrypted += cipher.final("base64");
    return encrypted;
  } catch (err) {
    console.error('AES Encryption Error:', err);
    return false;
  }
};

const decrypt_AES = (data) => {
  try {
    const decipher = crypto.createDecipheriv("aes-256-cbc", AES_KEY, AES_IV);
    let decrypted = decipher.update(data, "base64", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (err) {
    console.error('AES Decryption Error:', err);
    return false;
  }
};

const encrypt_EC = (data) => encryptData(data, EC_PUBLIC_KEY, crypto.constants.RSA_PKCS1_OAEP_PADDING);
const decrypt_EC = (data) => decryptData(data, EC_PRIVATE_KEY, crypto.constants.RSA_PKCS1_OAEP_PADDING);

const encrypt_DH = (data) => encryptData(data, DH_PUBLIC_KEY, crypto.constants.RSA_PKCS1_OAEP_PADDING);
const decrypt_DH = (data) => decryptData(data, DH_PRIVATE_KEY, crypto.constants.RSA_PKCS1_OAEP_PADDING);

const encrypt_ED25519 = (data) => encryptData(data, ed25519PublicKey, crypto.constants.RSA_PKCS1_OAEP_PADDING);
const decrypt_ED25519 = (data) => decryptData(data, ed25519PrivateKey, crypto.constants.RSA_PKCS1_OAEP_PADDING);

const encrypt_X25519 = (data) => encryptData(data, x25519PublicKey, crypto.constants.RSA_PKCS1_OAEP_PADDING);
const decrypt_X25519 = (data) => decryptData(data, x25519PrivateKey, crypto.constants.RSA_PKCS1_OAEP_PADDING);

const hybrid_encrypt_AES_RSA = (data) => {
  try {
    const aesEncryptedData = encrypt_AES(data);
    if (!aesEncryptedData) return false;
    return encrypt_RSA(aesEncryptedData);
  } catch (err) {
    console.error('Hybrid AES-RSA Encryption Error:', err);
    return false;
  }
};

const hybrid_decrypt_AES_RSA = (data) => {
  try {
    const rsaDecryptedData = decrypt_RSA(data);
    if (!rsaDecryptedData) return false;
    return decrypt_AES(rsaDecryptedData);
  } catch (err) {
    console.error('Hybrid AES-RSA Decryption Error:', err);
    return false;
  }
};

module.exports = {
  encrypt_RSA,
  decrypt_RSA,
  encrypt_RSA_OAEP,
  decrypt_RSA_OAEP,
  encrypt_RSA_PSS,
  decrypt_RSA_PSS,
  encrypt_RSA_CustomPadding,
  decrypt_RSA_CustomPadding,
  encrypt_RSA_CustomExponent,
  decrypt_RSA_CustomExponent,
  encrypt_AES,
  decrypt_AES,
  encrypt_EC,
  decrypt_EC,
  encrypt_DH,
  decrypt_DH,
  encrypt_ED25519,
  decrypt_ED25519,
  encrypt_X25519,
  decrypt_X25519,
  hybrid_encrypt_AES_RSA,
  hybrid_decrypt_AES_RSA
};
