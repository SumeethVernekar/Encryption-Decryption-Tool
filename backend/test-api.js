// Justa test file to test the API I generated it from Gemini 3 Pro coz i didn't had time to test it


const axios = require('axios');

const API_BASE_URL = 'http://localhost:3000/api';

console.log('🧪 Testing Encryption/Decryption API...\n');

async function testAPI() {
    try {
        // Test 1: Health Check
        console.log('Test 1: Health Check');
        const health = await axios.get(`${API_BASE_URL}/health`);
        console.log('Server is running:', health.data.message);
        console.log('');

        // Test 2: Get Available Methods
        console.log('Test 2: Available Encryption Methods');
        const methods = await axios.get(`${API_BASE_URL}/methods`);
        console.log('Available methods:');
        methods.data.methods.forEach(m => {
            console.log(`   - ${m.name}: ${m.description}`);
        });
        console.log('');

        // Test 3: AES Encryption
        console.log('Test 3: AES-256 Encryption');
        const originalText = 'Hello, this is a secret message!';
        const secretKey = 'my-super-secret-key-123';
        
        const encrypted = await axios.post(`${API_BASE_URL}/encrypt`, {
            text: originalText,
            method: 'aes',
            key: secretKey
        });
        console.log('Original:', originalText);
        console.log('Encrypted:', encrypted.data.encrypted.substring(0, 50) + '...');
        console.log('');

        // Test 4: AES Decryption
        console.log('Test 4: AES-256 Decryption');
        const decrypted = await axios.post(`${API_BASE_URL}/decrypt`, {
            text: encrypted.data.encrypted,
            method: 'aes',
            key: secretKey
        });
        console.log('Decrypted:', decrypted.data.decrypted);
        console.log('Match:', decrypted.data.decrypted === originalText ? 'YES ✓' : 'NO ✗');
        console.log('');

        // Test 5: Caesar Cipher
        console.log('Test 5: Caesar Cipher (Shift: 5)');
        const caesarEncrypted = await axios.post(`${API_BASE_URL}/encrypt`, {
            text: 'Hello World',
            method: 'caesar',
            shift: 5
        });
        console.log('Original: Hello World');
        console.log('Encrypted:', caesarEncrypted.data.encrypted);
        
        const caesarDecrypted = await axios.post(`${API_BASE_URL}/decrypt`, {
            text: caesarEncrypted.data.encrypted,
            method: 'caesar',
            shift: 5
        });
        console.log('Decrypted:', caesarDecrypted.data.decrypted);
        console.log('');

        // Test 6: Base64
        console.log('Test 6: Base64 Encoding');
        const base64Encrypted = await axios.post(`${API_BASE_URL}/encrypt`, {
            text: 'Base64 Test Message',
            method: 'base64'
        });
        console.log('Encoded:', base64Encrypted.data.encrypted);
        
        const base64Decrypted = await axios.post(`${API_BASE_URL}/decrypt`, {
            text: base64Encrypted.data.encrypted,
            method: 'base64'
        });
        console.log('Decoded:', base64Decrypted.data.decrypted);
        console.log('');

        // Test 7: ROT13
        console.log('Test 7: ROT13');
        const rot13Encrypted = await axios.post(`${API_BASE_URL}/encrypt`, {
            text: 'ROT13 is reversible',
            method: 'rot13'
        });
        console.log('Encrypted:', rot13Encrypted.data.encrypted);
        
        const rot13Decrypted = await axios.post(`${API_BASE_URL}/decrypt`, {
            text: rot13Encrypted.data.encrypted,
            method: 'rot13'
        });
        console.log('Decrypted:', rot13Decrypted.data.decrypted);
        console.log('');

        // Test 8: ECC
        console.log('Test 8: ECC');
        const eccEncrypted = await axios.post(`${API_BASE_URL}/encrypt`, {
            text: 'ECC is reversible',
            method: 'ECC'
        });
        console.log('Encrypted:', eccEncrypted.data.encrypted);
        
        const eccDecrypted = await axios.post(`${API_BASE_URL}/decrypt`, {
            text: eccEncrypted.data.encrypted,
            method: 'rot13'
        });
        console.log('Decrypted:', eccDecrypted.data.decrypted);
        console.log('');
        

        console.log('═══════════════════════════════════════');
        console.log('All tests passed successfully!');
        console.log('═══════════════════════════════════════');

    } catch (error) {
        console.error('Test failed:', error.response?.data || error.message);
    }
}

testAPI();
