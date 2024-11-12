const crypto = require('crypto');

class AESCipher {
    constructor(key) {
        this.blockSize = 16; // AES.block_size
        this.key = crypto.createHash('sha256').update(key).digest();
    }

    encrypt(plainText) {
        // AES Encryption
        const paddedPlainText = this.__pad(plainText);
        const iv = crypto.randomBytes(this.blockSize);
        const cipher = crypto.createCipheriv('aes-256-cbc', this.key, iv);
        let encryptedText = cipher.update(paddedPlainText, 'utf-8', 'base64');
        encryptedText += cipher.final('base64');
        
        // Combine IV and AES-encrypted text
        const aesEncryptedText = iv.toString('base64') + encryptedText;

        // Generate SHA-256 Hash of AES-encrypted text
        const hash = crypto.createHash('sha256').update(aesEncryptedText).digest('hex');

        // Now encrypt the AES-encrypted text with ChaCha20
        const chachaCipher = crypto.createCipheriv('chacha20', this.key.slice(0, 32), Buffer.alloc(8, 0)); // 32-byte key, 8-byte nonce (using zeros)
        let chachaEncryptedText = chachaCipher.update(aesEncryptedText, 'utf-8', 'base64');
        chachaEncryptedText += chachaCipher.final('base64');

        return {
            aesEncryptedText: aesEncryptedText,
            aesHash: hash,
            chachaEncryptedText: chachaEncryptedText
        };
    }

    decrypt(encryptedText) {
        // Decrypt the ChaCha20 text
        const chachaDecipher = crypto.createDecipheriv('chacha20', this.key.slice(0, 32), Buffer.alloc(8, 0));
        let chachaDecryptedText = chachaDecipher.update(encryptedText, 'base64', 'utf-8');
        chachaDecryptedText += chachaDecipher.final('utf-8');

        // Now decrypt the AES-encrypted text
        const aesEncryptedBuffer = Buffer.from(chachaDecryptedText, 'base64');
        const iv = aesEncryptedBuffer.slice(0, this.blockSize);
        const cipherText = aesEncryptedBuffer.slice(this.blockSize);
        const decipher = crypto.createDecipheriv('aes-256-cbc', this.key, iv);
        let decryptedText = decipher.update(cipherText, 'base64', 'utf-8');
        decryptedText += decipher.final('utf-8');
        return this.__unpad(decryptedText);
    }

    __pad(plainText) {
        const paddingLength = this.blockSize - (plainText.length % this.blockSize);
        const padding = String.fromCharCode(paddingLength).repeat(paddingLength);
        return plainText + padding;
    }

    __unpad(plainText) {
        const paddingLength = plainText.charCodeAt(plainText.length - 1);
        return plainText.slice(0, -paddingLength);
    }
}

// Example usage
const key = 'your-secret-key';
const aesCipher = new AESCipher(key);

const plainText = 'Hello, World!';
const result = aesCipher.encrypt(plainText);

// Log the encrypted texts and hash
console.log('AES Encrypted Text:', result.aesEncryptedText);
console.log('AES Hash:', result.aesHash);
console.log('ChaCha20 Encrypted Text:', result.chachaEncryptedText);

// Or log the entire result as a JSON string
console.log('Result:', JSON.stringify(result, null, 2));

module.exports = AESCipher;
