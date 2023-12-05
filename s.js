// @ts-check
import Crypto from "react-native-quick-crypto";
import { Buffer } from "@craftzdog/react-native-buffer";

export const base64ToHex = (str) => {
  const bin = Buffer.from(str, "base64").toString("binary");
  const hex = [];

  for (let i = 0; i < bin.length; ++i) {
    let tmp = bin.charCodeAt(i).toString(16);
    if (tmp.length === 1) tmp = "0" + tmp;
    hex.push(tmp);
  }

  return hex.join("");
};

export const rsaEncryption = (password) => {
  const { publicKey } = Crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
      cipher: "aes-256-cbc",
      passphrase: "top secret",
    },
  });
  console.log("🚀 ~ file: s.js:32 ~ rsaEncryption ~ publicKey:", publicKey);
  console.log("\n\n...", JSON.stringify(publicKey, null, 2), "...\n\n");
  const p0 = performance.now();
  const publicKeyString = `-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA34t3ax2ZykvBUBDlLYpu\nSMYPfjG6VIcd9diFZsP4N9anqCj/En3wsaeJcrZ7w+GlQKTOhDwh+i0D/JPT9oq5\nrLaW7Q8N7wzn1ISEecr6TWLUIwSapwp9rxrFb6/YAKSf7S/dUaYmGPmFFcroh3tT\n0nW0uDZSKxFiWy8De/99hlgAyxPqHB8znzgEnB+aROFzFVltbVuOcO/g7Q6mgWqV\nzZKlkE1+EROOMldqkS6VjIwXfosEv0P4bLTmBamL3YPkqk5TAErhc9auRdRyqwGb\nRv+ehQTnFspbE1vELqLkBq9nr+SQ5GdduukM3d5k/1Q+5PTq2qoZ6N9Gar/Z/rdd\nvQIDAQAB\n-----END PUBLIC KEY-----\n`;
  // const publicKeyString = `-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5i1CyXzrrP2LAWeD8eIw\n5oE6/u/0fbEbAJatvbp8Zk+uRnmL5Nz4vvPoXzvDkdRNb0aQokHic0boYpU0WWyS\nR+PzWpZBgq5bzx36llAzDR6DWmBwB80u+gYzG9JEA3ROkO8ZWLt1XyzxO2143Jrw\nuVF/rqNitmSM1wVFnjgUhSvbmJoxqulGFdXleuhJH8yH7rpsLKJqfkWYuqdV/ght\n56SIqB3DPnj+lzryNqsWVUNyLS3Wt/TYULYSM+8Nzg21VRNyhPik+BEjuAz9en/q\nBqf2vEdg3AODxW5GHk8RW59wf6HnDYoBkm7XIgIGeRjW3QYukWqbP4QqfN8wwx1B\nCVAH6fHc7LFwNMelzjMsahb7x4dIcWMHQ9ku0oiJNUliJgGgQ3Hw+gIRWTqUS1/r\nI5P8Qfo5IMyiytF60KmmyaDz+elyUmxeQ101UU+tNZcoJlJqXqfRvAE44P4xP6/M\nBKZQJuFD9BYA8qvzJvNjD5hkgl0gGeEwI/sH/YbJ/wx0ArCugJiy+82Mah9BBlNy\nvKsfJDI5fXPDXqK/B3gx2ztRd2VXQKNqW+yxl3YM9nwB7mhDQ+NIzciFJZUOn7i2\nbiDRflNprjidVYajoA3p61xFWinZ2xWvlbEu7Vkb4R6xdVisMbm9YF0VL/IKwD7A\n0hcfDQszdOxkz4iSaxOFbZ0CAwEAAQ==\n-----END PUBLIC KEY-----\n`;

  let key = {
    key: publicKeyString,
    padding: Crypto.constants.RSA_PKCS1_PADDING,
  };
  let encryptedValue = Crypto.publicEncrypt(
    key,
    Crypto.createHash("sha256").update(password).digest()
  ).toString("base64");
  const p1 = performance.now();
  const diff = p1 - p0;

  return encryptedValue;
};

export const aesEncryption = (data, key) => {
  const keySize = 256;
  const iterations = 1000;
  const salt = `randomsalt`;

  const aesKey = Crypto.pbkdf2Sync(key, salt, iterations, keySize / 8, "sha1");
  const iv = Crypto.pbkdf2Sync(key, salt, iterations, keySize / 16, "sha1");

  const cipher = Crypto.createCipheriv("aes-256-cbc", aesKey, iv);
  let encrypted = cipher.update(data, "utf8", "base64");
  encrypted += cipher.final("base64");

  const encryptedHex = base64ToHex(encrypted);
  const base64String = Buffer.from(encryptedHex, "hex").toString("base64");

  return base64String;
};

export const aesDecryption = (data, key) => {
  const keySize = 256;
  const iterations = 1000;
  const salt = `randomsalt`;

  const aesKey = Crypto.pbkdf2Sync(key, salt, iterations, keySize / 8, "sha1");
  const iv = Crypto.pbkdf2Sync(key, salt, iterations, keySize / 16, "sha1");

  const decipher = Crypto.createDecipheriv("aes-256-cbc", aesKey, iv);
  let decrypted = decipher.update(data, "base64", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
};

export const sha256 = (ascii) => {
  const hash = Crypto.createHash("sha256").update(ascii).digest("hex");
  return hash;
};

export const getReference = () => {
  let text = "";
  const possible =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.=";
  for (let index = 0; index < 15; index++)
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  return text;
};

export const test = async () => {
  try {
    const password = getReference();
    console.log("🚀 ~ file: s.js:121 ~ test ~ password:", password);
    const rsaKey = rsaEncryption(password);
    const data = { name: "Abdul" };
    console.log("🚀 ~ file: s.js:119 ~ test ~ rsaKey:", rsaKey);
    const encryptData = await aesEncryption(JSON.stringify(data), password);
    console.log("🚀 ~ file: s.js:125 ~ test ~ encryptData:", encryptData);
    console.log({
      key: rsaKey,
      data: encryptData,
    });
  } catch (error) {
    console.log("🚀 ~ file: s.js:88 ~ test ~ error:", error);
  }
};
