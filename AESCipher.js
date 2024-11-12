const crypto = require('crypto');

class AESCipher {
    constructor(key) {
        this.blockSize = 16; // AES.block_size
        this.key = crypto.createHash('sha256').update(key).digest();
    }

    encrypt(plainText) {
        const paddedPlainText = this.__pad(plainText);
        const iv = crypto.randomBytes(this.blockSize);
        const cipher = crypto.createCipheriv('aes-256-cbc', this.key, iv);
        let encryptedText = cipher.update(paddedPlainText, 'utf-8', 'base64');
        encryptedText += cipher.final('base64');
        
        // Combine IV and encrypted text
        const fullEncryptedText = iv.toString('base64') + encryptedText;
        
        // Generate a hash of the encrypted text
        const hash = crypto.createHash('sha256').update(fullEncryptedText).digest('hex');

        return {
            encryptedText: fullEncryptedText,
            hash: hash
        };
    }

    decrypt(encryptedText) {
        const encryptedBuffer = Buffer.from(encryptedText, 'base64');
        const iv = encryptedBuffer.slice(0, this.blockSize);
        const cipherText = encryptedBuffer.slice(this.blockSize);
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

module.exports = AESCipher;
