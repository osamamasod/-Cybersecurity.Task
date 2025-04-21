// Derive the AES key from the password using PBKDF2
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);

    try {
        const baseKey = await window.crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        console.log('Base Key Imported:', baseKey);

        return await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    } catch (err) {
        console.error('Error in deriveKey:', err);
        throw err;  // Re-throw the error to be handled later
    }
}

// Encrypt the file
async function encryptFile() {
    const fileInput = document.getElementById('fileInput');
    const passwordInput = document.getElementById('password');
    const outputFile = document.getElementById('outputFile');
    const status = document.getElementById('status');

    if (!fileInput.files.length || !passwordInput.value || !outputFile.value) {
        status.textContent = 'Please fill in all fields.';
        return;
    }

    const file = fileInput.files[0];
    const password = passwordInput.value;
    const salt = window.crypto.getRandomValues(new Uint8Array(16)); // Generate random salt
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Initialization vector (12 bytes for AES-GCM)

    console.log('Encryption Parameters:');
    console.log('Salt:', salt);
    console.log('IV:', iv);

    try {
        const key = await deriveKey(password, salt);
        const fileArrayBuffer = await file.arrayBuffer();

        console.log('File Data:', fileArrayBuffer);

        // Encrypt data
        const encryptedData = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            fileArrayBuffer
        );

        console.log('Encrypted Data:', encryptedData);

        // Create an ArrayBuffer with the encrypted data and authentication tag
        const encryptedDataArray = new Uint8Array(encryptedData);
        const authTag = encryptedDataArray.slice(-16); // Last 16 bytes are the authentication tag
        const ciphertext = encryptedDataArray.slice(0, encryptedDataArray.length - 16);

        console.log('Ciphertext:', ciphertext);
        console.log('Authentication Tag:', authTag);

        // Create a Blob containing the salt, iv, encrypted data, and authentication tag
        const outputBlob = new Blob([salt, iv, ciphertext, authTag], { type: 'application/octet-stream' });
        const outputUrl = URL.createObjectURL(outputBlob);

        // Trigger download
        const a = document.createElement('a');
        a.href = outputUrl;
        a.download = outputFile.value;
        a.click();

        status.textContent = 'File encrypted successfully.';
    } catch (err) {
        console.error('Encryption Error:', err);
        status.textContent = `Error: ${err.message}`;
    }
}

// Decrypt the file
async function decryptFile() {
    const fileInput = document.getElementById('fileInput');
    const passwordInput = document.getElementById('password');
    const outputFile = document.getElementById('outputFile');
    const status = document.getElementById('status');

    if (!fileInput.files.length || !passwordInput.value || !outputFile.value) {
        status.textContent = 'Please fill in all fields.';
        return;
    }

    const file = fileInput.files[0];
    const password = passwordInput.value;

    try {
        const fileBuffer = await file.arrayBuffer();

        // Extract salt, IV, encrypted data, and authentication tag
        const salt = new Uint8Array(fileBuffer.slice(0, 16)); // First 16 bytes are the salt
        const iv = new Uint8Array(fileBuffer.slice(16, 28)); // Next 12 bytes are the IV
        const encryptedData = fileBuffer.slice(28, fileBuffer.byteLength - 16); // The remaining data is the encrypted content
        const authTag = new Uint8Array(fileBuffer.slice(fileBuffer.byteLength - 16)); // Last 16 bytes are the authentication tag

        // Log the extracted data for debugging
        console.log('Extracted Salt:', salt);
        console.log('Extracted IV:', iv);
        console.log('Extracted Encrypted Data:', encryptedData);
        console.log('Extracted Authentication Tag:', authTag);

        const key = await deriveKey(password, salt); // Ensure same key derivation as encryption
        console.log('Base Key Imported:', key);

        // Log the decryption params
        const decryptParams = {
            name: 'AES-GCM',
            iv: iv,
            tagLength: 128 // AES-GCM tag length must be 128 bits (16 bytes)
        };

        console.log('Decrypt Params:', decryptParams);

        // Concatenate the authentication tag with the encrypted data for decryption
        const dataWithTag = new Uint8Array(encryptedData.byteLength + authTag.byteLength);
        dataWithTag.set(new Uint8Array(encryptedData), 0); // Copy encrypted data
        dataWithTag.set(new Uint8Array(authTag), encryptedData.byteLength); // Append the tag

        // Decrypt data with the concatenated authentication tag
        try {
            const decryptedData = await window.crypto.subtle.decrypt(
                decryptParams,
                key,
                dataWithTag
            );
            console.log('Decrypted Data:', decryptedData);

            // Create a Blob from the decrypted data
            const outputBlob = new Blob([decryptedData], { type: 'application/octet-stream' });
            const outputUrl = URL.createObjectURL(outputBlob);

            // Trigger download
            const a = document.createElement('a');
            a.href = outputUrl;
            a.download = outputFile.value;
            a.click();

            status.textContent = 'File decrypted successfully.';
        } catch (err) {
            console.error('Decryption Error with Tag:', err);
            status.textContent = `Decryption Error: ${err.message}`;
        }
    } catch (err) {
        console.error('General Error:', err);
        status.textContent = `Error: ${err.message}`;
    }
}

// Add event listeners to the buttons
document.getElementById('encryptBtn').addEventListener('click', encryptFile);
document.getElementById('decryptBtn').addEventListener('click', decryptFile);
