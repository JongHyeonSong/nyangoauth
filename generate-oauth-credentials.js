const crypto = require("crypto");

// client_id: 13자리 숫자 (타임스탬프 기반)
const timestamp = Date.now().toString();
const clientId = timestamp.slice(-13);

// client_secret: 32자리 랜덤 문자열 (알파벳 대소문자 + 숫자 + 특수문자)
const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+';
let clientSecret = '';
for (let i = 0; i < 32; i++) {
    clientSecret += chars.charAt(Math.floor(Math.random() * chars.length));
}

// authorization_code: 32자리 랜덤 문자열 (알파벳 대소문자 + 숫자)
const codeChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
let authCode = '';
for (let i = 0; i < 32; i++) {
    authCode += codeChars.charAt(Math.floor(Math.random() * codeChars.length));
}

console.log({
    clientId,
    clientSecret,
    authCode,
    redirectUri: "http://localhost:3333/rd"
}); 