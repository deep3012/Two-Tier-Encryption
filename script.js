function encryptText() {
    const inputText = document.getElementById('inputText').value;
    fetch('/encrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({ inputText })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('encryptedText').value = data.encryptedText;
    })
    .catch(error => console.error('Error:', error));
}
