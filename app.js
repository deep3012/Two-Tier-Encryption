const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors'); // Add this
const AESCipher = require('./AESCipher');

const app = express();
const port = 3001;

app.use(cors()); // Enable CORS
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public'));

app.post('/encrypt', (req, res) => {
    const { inputText } = req.body;

    console.log('Received inputText:', inputText);

    if (!inputText) {
        console.error('No input text provided');
        return res.status(400).json({ error: 'No input text provided' });
    }

    try {
        const aesObject = new AESCipher("Deep");
        const aesEncryptedText = aesObject.encrypt(inputText);
        console.log('AES Encrypted Text:', aesEncryptedText);
        res.json({ aesEncryptedText });
    } catch (error) {
        console.error('Encryption error:', error.stack || error.message);
        res.status(500).json({ error: `Encryption failed: ${error.message}` });
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
