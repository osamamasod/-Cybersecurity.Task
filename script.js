
// Derives a secure AES-GCM key from the user password and random salt
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);

    try {
        // Import password into a base crypto key
        const baseKey = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        // Derive a strong AES-GCM encryption key from the base key
        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000, // High iteration count for security
                hash: 'SHA-256'
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    } catch (error) {
        console.error('Error deriving key:', error);
        throw error;
    }
}

// Creates a download link for a blob and triggers it automatically
function triggerDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url); // Clean up the temporary URL
}

// Updates the status message on the page
function showStatus(message) {
    const status = document.getElementById('status');
    status.textContent = message;
}

// Retrieves the user input values (file, password, output filename)
function getInputs() {
    const fileInput = document.getElementById('fileInput');
    const passwordInput = document.getElementById('password');
    const outputFile = document.getElementById('outputFile');

    return {
        file: fileInput.files[0],
        password: passwordInput.value,
        outputFileName: outputFile.value
    };
}



// Handles the encryption flow
async function encryptFile() {
    const { file, password, outputFileName } = getInputs();
    if (!file || !password || !outputFileName) {
        showStatus('Please fill in all fields.');
        return;
    }

    // : Generate random salt and IV (Initialization Vector)
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    try {
        // : Derive a key from the password and salt
        const key = await deriveKey(password, salt);

        //  Read file content into an ArrayBuffer
        const fileArrayBuffer = await file.arrayBuffer();

        //  Encrypt the file using AES-GCM
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            fileArrayBuffer
        );

        //  Separate ciphertext and authentication tag
        const encryptedArray = new Uint8Array(encrypted);
        const authTag = encryptedArray.slice(-16); // Last 16 bytes
        const ciphertext = encryptedArray.slice(0, -16);

        //  Bundle salt, IV, ciphertext, and auth tag into one Blob
        const outputBlob = new Blob([salt, iv, ciphertext, authTag], { type: 'application/octet-stream' });

        //  Trigger download of the encrypted file
        triggerDownload(outputBlob, outputFileName);

        showStatus('File encrypted successfully.');
    } catch (error) {
        console.error('Encryption Error:', error);
        showStatus(`Encryption Error: ${error.message}`);
    }
}

// Handles the decryption flow
async function decryptFile() {
    const { file, password, outputFileName } = getInputs();
    if (!file || !password || !outputFileName) {
        showStatus('Please fill in all fields.');
        return;
    }

    try {
        // : Read the encrypted file into an ArrayBuffer
        const fileBuffer = await file.arrayBuffer();

        // : Extract salt, IV, encrypted content, and auth tag from file
        const salt = new Uint8Array(fileBuffer.slice(0, 16));
        const iv = new Uint8Array(fileBuffer.slice(16, 28));
        const encryptedData = fileBuffer.slice(28, fileBuffer.byteLength - 16);
        const authTag = new Uint8Array(fileBuffer.slice(fileBuffer.byteLength - 16));

        // : Derive the same key from the password and extracted salt
        const key = await deriveKey(password, salt);

        // : Merge encryptedData and authTag for AES-GCM decryption
        const dataWithTag = new Uint8Array(encryptedData.byteLength + authTag.byteLength);
        dataWithTag.set(new Uint8Array(encryptedData));
        dataWithTag.set(authTag, encryptedData.byteLength);

        // : Decrypt the content
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv, tagLength: 128 },
            key,
            dataWithTag
        );

        // : Create a Blob from the decrypted content and download it
        const outputBlob = new Blob([decrypted], { type: 'application/octet-stream' });
        triggerDownload(outputBlob, outputFileName);

        showStatus('File decrypted successfully.');
    } catch (error) {
        console.error('Decryption Error:', error);
        showStatus(`Decryption Error: ${error.message}`);
    }
}



document.getElementById('encryptBtn').addEventListener('click', encryptFile);


document.getElementById('decryptBtn').addEventListener('click', decryptFile);
