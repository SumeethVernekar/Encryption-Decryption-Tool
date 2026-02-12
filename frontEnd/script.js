// API Configuration
const API_BASE_URL = 'http://localhost:3000/api';

// DOM Elements
let fileInput, inputTextarea, outputTextarea, encryptBtn, decryptBtn, clearBtn, copyBtn;
let methodSelect, keyInput, shiftInput, keyContainer, shiftContainer;

document.addEventListener("DOMContentLoaded", function () {
    // Initialize DOM elements
    fileInput = document.getElementById("fileInput");
    inputTextarea = document.getElementById("ip");
    outputTextarea = document.getElementById("op");
    encryptBtn = document.querySelector(".encrypt");
    decryptBtn = document.querySelector(".decrypt");
    clearBtn = document.querySelector(".clearAll");
    copyBtn = document.getElementById("copy");
    methodSelect = document.getElementById("method");
    keyInput = document.getElementById("key");
    shiftInput = document.getElementById("shift");
    keyContainer = document.querySelector(".key-container");
    shiftContainer = document.querySelector(".shift-container");

    // Load available encryption methods
    loadEncryptionMethods();

    // File input handler
    fileInput.addEventListener("change", handleFileSelect);

    // Button handlers
    encryptBtn.addEventListener("click", handleEncrypt);
    decryptBtn.addEventListener("click", handleDecrypt);
    clearBtn.addEventListener("click", clearAll);
    copyBtn.addEventListener("click", copyToClipboard);

    // Method selection handler
    if (methodSelect) {
        methodSelect.addEventListener("change", updateKeyInputs);
    }

    // Check API health
    checkAPIHealth();
});

/**
 * Check if API is running
 */
async function checkAPIHealth() {
    try {
        const response = await fetch(`${API_BASE_URL}/health`);
        const data = await response.json();
        console.log('API Status:', data);
        showNotification('Connected to server ✓', 'success');
    } catch (error) {
        console.error('API health check failed:', error);
        showNotification('Server connection failed. Please start the backend server.', 'error');
    }
}

/**
 * Load available encryption methods from API
 */
async function loadEncryptionMethods() {
    try {
        const response = await fetch(`${API_BASE_URL}/methods`);
        const data = await response.json();
        
        if (methodSelect && data.methods) {
            data.methods.forEach(method => {
                const option = document.createElement('option');
                option.value = method.id;
                option.textContent = `${method.name} - ${method.description}`;
                option.dataset.requiresKey = method.requiresKey;
                methodSelect.appendChild(option);
            });
            updateKeyInputs();
        }
    } catch (error) {
        console.error('Failed to load encryption methods:', error);
    }
}

/**
 * Update key/shift input visibility based on selected method
 */
function updateKeyInputs() {
    const selectedMethod = methodSelect.value;
    
    if (keyContainer && shiftContainer) {
        // Hide all by default
        keyContainer.style.display = 'none';
        shiftContainer.style.display = 'none';
        
        // Show based on method
        switch (selectedMethod) {
            case 'aes':
                keyContainer.style.display = 'block';
                break;
            case 'caesar':
                shiftContainer.style.display = 'block';
                break;

            case 'ecc':
                keyContainer.style.display = 'block';
                keyInput.placeholder = "Enter Public Key (Encrypt) / Private Key (Decrypt)";
                break;
        }
    }
}

/**
 * Handle file selection
 */
function handleFileSelect() {
    const file = fileInput.files[0];
    if (!file) {
        showNotification("No file selected", 'warning');
        return;
    }

    const reader = new FileReader();

    reader.onload = function () {
        inputTextarea.value = reader.result;
        showNotification(`File "${file.name}" loaded successfully`, 'success');
    };

    reader.onerror = function () {
        showNotification("Error reading file", 'error');
    };

    reader.readAsText(file);
}

/**
 * Handle encryption
 */
async function handleEncrypt() {
    const text = inputTextarea.value.trim();
    
    if (!text) {
        showNotification("Please enter text to encrypt", 'warning');
        return;
    }

    const method = methodSelect ? methodSelect.value : 'aes';
    const key = keyInput ? keyInput.value : '';
    const shift = shiftInput ? parseInt(shiftInput.value) || 3 : 3;

    // Validate AES key
    if (method === 'aes' && !key) {
        showNotification("Please enter a secret key for AES encryption", 'warning');
        return;
    }

    try {
        showLoading(true);
        
        const response = await fetch(`${API_BASE_URL}/encrypt`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                text: text,
                method: method,
                key: key,
                shift: shift
            })
        });
        
        const data = await response.json();

        if (response.ok && data.success) {
            if (method === "ecc") {
                outputTextarea.value = JSON.stringify(data.encrypted, null, 2);
            } else {
                outputTextarea.value = data.encrypted;
            }

            showNotification(`Text encrypted successfully using ${method.toUpperCase()}`, 'success');
        } else {
            showNotification(data.error || 'Encryption failed', 'error');
        }
    } catch (error) {
        console.error('Encryption error:', error);
        showNotification('Encryption failed. Please ensure the server is running.', 'error');
    } finally {
        showLoading(false);
    }
}

/**
 * Handle decryption
 */
async function handleDecrypt() {
    const text = inputTextarea.value.trim();
    
    if (!text) {
        showNotification("Please enter text to decrypt", 'warning');
        return;
    }

    const method = methodSelect ? methodSelect.value : 'aes';
    const key = keyInput ? keyInput.value : '';
    const shift = shiftInput ? parseInt(shiftInput.value) || 3 : 3;

    // Validate AES key
    if (method === 'aes' && !key) {
        showNotification("Please enter a secret key for AES decryption", 'warning');
        return;
    }

    try {
        showLoading(true);
        
        const response = await fetch(`${API_BASE_URL}/decrypt`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                text: text,
                method: method,
                key: key,
                shift: shift
            })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            outputTextarea.value = data.decrypted;
            showNotification(`Text decrypted successfully using ${method.toUpperCase()}`, 'success');
        } else {
            showNotification(data.error || 'Decryption failed', 'error');
        }
    } catch (error) {
        console.error('Decryption error:', error);
        showNotification('Decryption failed. Please ensure the server is running.', 'error');
    } finally {
        showLoading(false);
    }

    //ECC
    let requestBody = {
    text: text,
    method: method,
    key: key,
    shift: shift
    };

    if (method === "ecc") {
    try {
        requestBody.text = JSON.parse(text);
    } catch (e) {
        showNotification("Invalid ECC encrypted format", "error");
        showLoading(false);
        return;
    }
}


}

/**
 * Clear all fields
 */
function clearAll() {
    inputTextarea.value = '';
    outputTextarea.value = '';
    if (keyInput) keyInput.value = '';
    if (shiftInput) shiftInput.value = '3';
    fileInput.value = '';
    showNotification('All fields cleared', 'info');
}

/**
 * Copy output to clipboard
 */
function copyToClipboard() {
    const text = outputTextarea.value;
    
    if (!text) {
        showNotification('Nothing to copy', 'warning');
        return;
    }

    navigator.clipboard.writeText(text).then(() => {
        showNotification('Copied to clipboard!', 'success');
    }).catch(err => {
        console.error('Failed to copy:', err);
        showNotification('Failed to copy to clipboard', 'error');
    });
}

/**
 * Show loading state
 */
function showLoading(isLoading) {
    if (isLoading) {
        encryptBtn.disabled = true;
        decryptBtn.disabled = true;
        encryptBtn.textContent = 'Processing...';
        decryptBtn.textContent = 'Processing...';
    } else {
        encryptBtn.disabled = false;
        decryptBtn.disabled = false;
        encryptBtn.textContent = 'Encrypt';
        decryptBtn.textContent = 'Decrypt';
    }
}

/**
 * Show notification to user
 */
function showNotification(message, type = 'info') {
    // Create notification element if it doesn't exist
    let notification = document.getElementById('notification');
    
    if (!notification) {
        notification = document.createElement('div');
        notification.id = 'notification';
        document.body.appendChild(notification);
    }

    // Set notification content and type
    notification.textContent = message;
    notification.className = `notification ${type} show`;

    // Auto-hide after 3 seconds
    setTimeout(() => {
        notification.classList.remove('show');
    }, 3000);
}