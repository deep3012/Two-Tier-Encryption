const AESCipher = require('./AESCipher');

const aesObject = new AESCipher("Deep");
const testText = "Hello, World!";

try {
    const encryptedText = aesObject.encrypt(testText);
    console.log('Encrypted Text:', encryptedText);

    const decryptedText = aesObject.decrypt(encryptedText);
    console.log('Decrypted Text:', decryptedText);
} catch (error) {
    console.error('Encryption/Decryption error:', error.message);
}
