const express = require('express')
const app = express()
const path = require("path")
const session = require('express-session')
const FileStore = require('session-file-store')(session)
const bcrypt = require('bcrypt')
const crypto = require('crypto')

const SimplePropertiesDB = require("simple-properties-db")
const spd = new SimplePropertiesDB("")

// userId 생성 함수
function generateUserId() {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < 6; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// client_id: UUID v4
function generateClientId() {
    return crypto.randomUUID();
}

// client_secret: base64 encoded 256-bit key
function generateClientSecret() {
    return crypto.randomBytes(32).toString("base64");
}

// code: URL-safe 128-bit random token
function generateAuthCode() {
    return crypto.randomBytes(16).toString("hex");
}

// 세션 설정
app.use(session({
    secret: 'petnyang-oauth-secret-key', // 세션 암호화 키
    resave: false,
    saveUninitialized: true,
    store: new FileStore({
        path: path.join(__dirname, 'sessions'), // 절대 경로 사용
        ttl: 86400, // 세션 유효 시간 (초 단위, 24시간)
        reapInterval: 3600, // 만료된 세션 정리 주기 (초 단위, 1시간)
        secret: 'petnyang-oauth-secret-key', // 세션 파일 암호화 키
        retries: 0, // 재시도 횟수 제한
        logFn: function(s) { console.log(s); } // 로그 함수 추가
    }),
    cookie: { 
        secure: false, // 개발 환경에서는 false, 프로덕션에서는 true로 설정
        maxAge: 24 * 60 * 60 * 1000 // 24시간
    }
}));

// JSON 파싱을 위한 미들웨어 추가
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, "public")))

// 로그인 라우터
app.post("/signup", async (req, res) => {
    try {
        const { name, email, password } = req.body;
        console.log(req.body)
        
        if (!email || !password) {
            return res.status(400).json({ message: "사용자 이름과 비밀번호를 모두 입력해주세요." });
        }
        const userList = JSON.parse(spd.get("userList") || "[]")

        const isDup = userList.find(user=> user.email === email)
        if(isDup){
            return res.status(500).json({message: "dub dub"})
        }

        // userId 생성 (6자리 숫자+영소문자)
        let userId;
        let isUnique = false;
        while (!isUnique) {
            userId = generateUserId();
            isUnique = !userList.some(user => user.userId === userId);
        }

        const newUser = {
            userId,
            email,
            password, // 암호화하지 않고 그대로 저장
            name,
            createdAt: new Date().toISOString()
        }

        userList.push(newUser)
        spd.set("userList", JSON.stringify(userList))

        res.status(200).json({ 
            message: "회원가입 성공",
            userId: userId
        });
    } catch (error) {
        console.error("회원가입 에러:", error);
        res.status(500).json({ message: "서버 에러가 발생했습니다." });
    }
});

app.post("/login", async (req, res) => {
    try {
        const { email, password, client_id, redirect_uri, state } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ message: "이메일과 비밀번호를 모두 입력해주세요." });
        }

        const userList = JSON.parse(spd.get("userList") || "[]");
        const user = userList.find(user => user.email === email && user.password === password);

        if (!user) {
            return res.status(401).json({ message: "이메일 또는 비밀번호가 올바르지 않습니다." });
        }

        // OAuth 로그인인 경우 clientId 검증
        if (client_id) {
            const serviceList = JSON.parse(spd.get("serviceList") || "[]");
            const service = serviceList.find(s => s.id === client_id && s.userId === user.userId);
            
            if (client_id !== 'masterkey' && !service) {
                return res.status(403).json({ 
                    message: "해당 서비스에 대한 접근 권한이 없습니다." 
                });
            }

            // 리다이렉트 URL 검증
            if (client_id !== 'masterkey' && !service.redirectUrls.includes(redirect_uri)) {
                return res.status(400).json({ message: "유효하지 않은 리다이렉트 URL입니다." });
            }

            // 인증 코드 생성
            const authCode = generateAuthCode();

            // 인증 코드 저장
            const authCodes = JSON.parse(spd.get("authCodes") || "[]");
            authCodes.push({
                code: authCode,
                clientId: client_id,
                userId: user.userId,
                redirectUri: redirect_uri,
                state: state,
                createdAt: new Date().toISOString(),
                expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString() // 10분 후 만료
            });
            spd.set("authCodes", JSON.stringify(authCodes));

            // 세션에 userId 저장
            req.session.userId = user.userId;

            res.status(200).json({ 
                message: "로그인 성공",
                code: authCode,
                state: state
            });
        } else {
            // 일반 로그인
            req.session.userId = user.userId;
            res.status(200).json({ 
                message: "로그인 성공",
                user: {
                    userId: user.userId,
                    email: user.email,
                    name: user.name
                }
            });
        }
    } catch (error) {
        console.error("로그인 에러:", error);
        res.status(500).json({ message: "서버 에러가 발생했습니다." });
    }
});

// 사용자 목록 조회 API
app.get("/users", (req, res) => {
    try {
        const userList = JSON.parse(spd.get("userList") || "[]");
        // 모든 사용자 정보 전송 (비밀번호 포함)
        res.json(userList);
    } catch (error) {
        console.error("사용자 목록 조회 에러:", error);
        res.status(500).json({ message: "서버 에러가 발생했습니다." });
    }
});

// 서비스 등록 API
app.post("/api/services", async (req, res) => {
    try {
        const { serviceName, serviceDomains, redirectUrls } = req.body;
        const userId = req.session.userId;

        // 로그인 체크
        if (!userId) {
            return res.status(401).json({ message: "로그인이 필요합니다." });
        }

        // 사용자 정보 가져오기
        const userList = JSON.parse(spd.get("userList") || "[]");
        const user = userList.find(u => u.userId === userId);
        
        if (!user) {
            return res.status(401).json({ message: "사용자 정보를 찾을 수 없습니다." });
        }

        // 필수 필드 검증
        if (!serviceName || !serviceDomains || !serviceDomains.length || !redirectUrls || !redirectUrls.length) {
            return res.status(400).json({ message: "모든 필드를 입력해주세요." });
        }

        // 도메인 형식 검증
        const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(:\d+)?$|^localhost(:\d+)?$/;
        for (const domain of serviceDomains) {
            if (!domainRegex.test(domain.trim())) {
                return res.status(400).json({ 
                    message: `올바른 도메인 형식이 아닙니다: ${domain}` 
                });
            }
        }

        // URL 형식 검증
        const urlRegex = /^https?:\/\/.+/;
        for (const url of redirectUrls) {
            if (!urlRegex.test(url.trim())) {
                return res.status(400).json({ 
                    message: `올바른 URL 형식이 아닙니다: ${url}` 
                });
            }
        }

        // 서비스 목록 가져오기
        const serviceList = JSON.parse(spd.get("serviceList") || "[]");


        // 클라이언트 ID와 시크릿 생성
        const clientId = generateClientId();
        const clientSecret = generateClientSecret();

        // 새 서비스 생성
        const newService = {
            id: clientId,
            clientSecret: clientSecret,
            userId: user.userId,
            userName: user.name,
            serviceName,
            serviceDomains: serviceDomains.map(d => d.trim()),
            redirectUrls: redirectUrls.map(u => u.trim()),
            createdAt: new Date().toISOString()
        };

        // 서비스 목록에 추가
        serviceList.push(newService);
        spd.set("serviceList", JSON.stringify(serviceList));

        res.status(201).json({
            message: "서비스가 성공적으로 등록되었습니다.",
            service: {
                ...newService,
                clientSecret // 클라이언트 시크릿은 최초 1회만 반환
            }
        });
    } catch (error) {
        console.error("서비스 등록 에러:", error);
        res.status(500).json({ message: "서버 에러가 발생했습니다." });
    }
});

// 사용자의 서비스 목록 조회 API
app.get("/api/my-services", (req, res) => {
    try {
        const userId = req.session.userId;

        // 로그인 체크
        if (!userId) {
            return res.status(401).json({ message: "로그인이 필요합니다." });
        }

        const serviceList = JSON.parse(spd.get("serviceList") || "[]");
        // 현재 로그인한 사용자의 서비스만 필터링하고 클라이언트 시크릿 포함
        const myServices = serviceList
            .filter(service => service.userId === userId)
            .map(service => ({
                ...service,
                clientSecret: service.clientSecret // 클라이언트 시크릿 포함
            }));
        res.json(myServices);
    } catch (error) {
        console.error("서비스 목록 조회 에러:", error);
        res.status(500).json({ message: "서버 에러가 발생했습니다." });
    }
});

// 서비스 목록 조회 API
app.get("/api/services", (req, res) => {
    try {
        const serviceList = JSON.parse(spd.get("serviceList") || "[]");
        res.json(serviceList);
    } catch (error) {
        console.error("서비스 목록 조회 에러:", error);
        res.status(500).json({ message: "서버 에러가 발생했습니다." });
    }
});

// 서비스 업데이트 API
app.put("/api/services/:serviceId", async (req, res) => {
    try {
        const { serviceId } = req.params;
        const { serviceName, serviceDomains, redirectUrls } = req.body;
        const userId = req.session.userId;

        // 로그인 체크
        if (!userId) {
            return res.status(401).json({ message: "로그인이 필요합니다." });
        }

        // 서비스 목록 가져오기
        const serviceList = JSON.parse(spd.get("serviceList") || "[]");
        const serviceIndex = serviceList.findIndex(service => service.id === serviceId);

        // 서비스 존재 여부 확인
        if (serviceIndex === -1) {
            return res.status(404).json({ message: "서비스를 찾을 수 없습니다." });
        }

        // 권한 확인
        if (serviceList[serviceIndex].userId !== userId) {
            return res.status(403).json({ message: "서비스를 수정할 권한이 없습니다." });
        }

        // 필수 필드 검증
        if (!serviceName || !serviceDomains || !serviceDomains.length || !redirectUrls || !redirectUrls.length) {
            return res.status(400).json({ message: "모든 필드를 입력해주세요." });
        }

        // 도메인 형식 검증
        const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(:\d+)?$|^localhost(:\d+)?$/;
        for (const domain of serviceDomains) {
            if (!domainRegex.test(domain.trim())) {
                return res.status(400).json({ 
                    message: `올바른 도메인 형식이 아닙니다: ${domain}` 
                });
            }
        }

        // URL 형식 검증
        const urlRegex = /^https?:\/\/.+/;
        for (const url of redirectUrls) {
            if (!urlRegex.test(url.trim())) {
                return res.status(400).json({ 
                    message: `올바른 URL 형식이 아닙니다: ${url}` 
                });
            }
        }


        // 서비스 정보 업데이트
        serviceList[serviceIndex] = {
            ...serviceList[serviceIndex],
            serviceName,
            serviceDomains: serviceDomains.map(d => d.trim()),
            redirectUrls: redirectUrls.map(u => u.trim()),
            updatedAt: new Date().toISOString()
        };

        spd.set("serviceList", JSON.stringify(serviceList));

        res.json({
            message: "서비스가 성공적으로 업데이트되었습니다.",
            service: serviceList[serviceIndex]
        });
    } catch (error) {
        console.error("서비스 업데이트 에러:", error);
        res.status(500).json({ message: "서버 에러가 발생했습니다." });
    }
});

// 서비스 ID로 서비스 정보 조회 API
app.get("/api/services/:serviceId", (req, res) => {
    try {
        const { serviceId } = req.params;
        const serviceList = JSON.parse(spd.get("serviceList") || "[]");
        const service = serviceList.find(s => s.id === serviceId);

        if (!service) {
            return res.status(404).json({ message: "서비스를 찾을 수 없습니다." });
        }

        res.json(service);
    } catch (error) {
        console.error("서비스 조회 에러:", error);
        res.status(500).json({ message: "서버 에러가 발생했습니다." });
    }
});

// 서비스 정보 조회 API
app.get("/api/services/:clientId", (req, res) => {
    try {
        const { clientId } = req.params;
        const serviceList = JSON.parse(spd.get("serviceList") || "[]");
        const service = serviceList.find(s => s.id === clientId);
        
        if (!service) {
            return res.status(404).json({ message: "서비스를 찾을 수 없습니다." });
        }

        // 클라이언트 시크릿은 제외하고 반환
        const { clientSecret, ...serviceInfo } = service;
        res.json(serviceInfo);
    } catch (error) {
        console.error("서비스 정보 조회 에러:", error);
        res.status(500).json({ message: "서버 에러가 발생했습니다." });
    }
});

// OAuth 인증 코드 생성 API
app.post("/oauth/authorize", async (req, res) => {
    try {
        const { client_id, redirect_uri, state } = req.body;
        const userId = req.session.userId;

        // 로그인 체크
        if (!userId) {
            return res.status(401).json({ message: "로그인이 필요합니다." });
        }

        // 서비스 정보 가져오기
        const serviceList = JSON.parse(spd.get("serviceList") || "[]");
        const service = serviceList.find(s => s.id === client_id);

        if (!service) {
            return res.status(404).json({ message: "서비스를 찾을 수 없습니다." });
        }

        // 리다이렉트 URL 검증
        if (!service.redirectUrls.includes(redirect_uri)) {
            return res.status(400).json({ message: "유효하지 않은 리다이렉트 URL입니다." });
        }

        // 인증 코드 생성
        const authCode = generateAuthCode();

        // 인증 코드 저장
        const authCodes = JSON.parse(spd.get("authCodes") || "[]");
        authCodes.push({
            code: authCode,
            clientId: client_id,
            userId: userId,
            redirectUri: redirect_uri,
            state: state,
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString() // 10분 후 만료
        });
        spd.set("authCodes", JSON.stringify(authCodes));

        // 원래 redirect_uri로 리다이렉트
        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.set('code', authCode);
        if (state) {
            redirectUrl.searchParams.set('state', state);
        }
        res.redirect(redirectUrl.toString());
    } catch (error) {
        console.error("인증 코드 생성 에러:", error);
        res.status(500).json({ message: "서버 에러가 발생했습니다." });
    }
});

// OAuth 토큰 발급
app.post('/oauth/token', express.json(), (req, res) => {
    const { client_id, client_secret, code, redirect_uri, grant_type } = req.body;

    // 필수 파라미터 검증
    if (!client_id || !client_secret || !code || !redirect_uri || grant_type !== 'authorization_code') {
        return res.status(400).json({
            error: '잘못된 요청입니다.',
            message: '필수 파라미터가 누락되었거나 잘못되었습니다.'
        });
    }

    // Masterkey bypass
    if (client_id === 'masterkey' && client_secret === 'mastersecret') {
        // Issue token without further checks
        const access_token = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        return res.json({
            access_token,
            token_type: 'Bearer',
            expires_in: 3600,
            scope: 'read',
            created_at: Math.floor(Date.now() / 1000)
        });
    }

    // 서비스 목록 가져오기
    const serviceList = JSON.parse(spd.get("serviceList") || "[]");

    // 클라이언트 인증
    const service = serviceList.find(s => s.id === client_id && s.clientSecret === client_secret);
    if (!service) {
        return res.status(401).json({
            error: '클라이언트 인증에 실패했습니다.',
            message: '클라이언트 ID 또는 시크릿이 올바르지 않습니다.'
        });
    }

    // 리다이렉트 URI 검증
    if (!service.redirectUrls.includes(redirect_uri)) {
        return res.status(400).json({
            error: '유효하지 않은 리다이렉트 URI입니다.',
            message: '등록되지 않은 리다이렉트 URI입니다.'
        });
    }

    // 액세스 토큰 생성
    const access_token = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    res.json({
        access_token,
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'read',
        created_at: Math.floor(Date.now() / 1000)
    });
});

// OAuth 사용자 정보
app.get('/oauth/userinfo', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: '인증이 필요합니다.' });
    }

    const token = authHeader.split(' ')[1];
    // TODO: 토큰 검증 로직 추가

    // 임시로 첫 번째 사용자 정보 반환
    const userList = JSON.parse(spd.get("userList") || "[]");
    if (userList.length > 0) {
        const user = userList[0];
        res.json({
            userId: user.userId,
            email: user.email,
            name: user.name
        });
    } else {
        res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    }
});

// OAuth 인증 페이지
app.get('/oauth/authorize', (req, res) => {
    const { client_id, redirect_uri, response_type } = req.query;

    // 필수 파라미터 검증
    if (!client_id || !redirect_uri || response_type !== 'code') {
        return res.status(400).json({ message: "잘못된 요청입니다." });
    }

    // Masterkey bypass
    if (client_id === 'masterkey') {
        // Allow any redirect_uri for masterkey
        return res.redirect(`/oauth-login.html?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}`);
    }

    // 서비스 목록 가져오기
    const serviceList = JSON.parse(spd.get("serviceList") || "[]");
    // 클라이언트 ID 검증
    const service = serviceList.find(s => s.id === client_id);
    if (!service) {
        return res.status(403).json({ 
            message: "존재하지 않는 서비스 입니다." 
        });
    }

    // 리다이렉트 URI 검증
    if (!service.redirectUrls.includes(redirect_uri)) {
        return res.status(400).json({ 
            message: "유효하지 않은 리다이렉트 URI입니다." 
        });
    }

    // OAuth 전용 로그인 페이지로 리다이렉트
    res.redirect(`/oauth-login.html?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}`);
});

// OAuth 서비스 정보 조회 API
app.get("/api/oauth/service-info", (req, res) => {
    try {
        const { client_id } = req.query;
        
        console.log('요청된 client_id:', client_id);
        
        if (!client_id) {
            return res.status(400).json({ message: "client_id가 필요합니다." });
        }
        if(client_id === 'masterkey'){
            return res.json({
                serviceName: "Masterkey",
                serviceDomains: ["localhost"],
                redirectUrls: ["http://localhost:3000/demoClient/callback"]
            });
        }

        const serviceList = JSON.parse(spd.get("serviceList") || "[]");
        console.log('전체 서비스 목록:', serviceList);
        
        const service = serviceList.find(s => s.id === client_id);
        console.log('찾은 서비스:', service);
        
        if (!service) {
            return res.status(404).json({ message: "서비스를 찾을 수 없습니다." });
        }

        // 민감한 정보는 제외하고 반환
        const { clientSecret, ...serviceInfo } = service;
        res.json(serviceInfo);
    } catch (error) {
        console.error("서비스 정보 조회 에러:", error);
        res.status(500).json({ message: "서버 에러가 발생했습니다." });
    }
});

// ===== Demo Client OAuth Endpoints =====

// Start OAuth flow (redirect to authorization endpoint)
app.get('/demoClient/auth', (req, res) => {
    // Use test client credentials
    const client_id = 'masterkey';
    const redirect_uri = '/demoClient/callback'; // Relative path
    const state = crypto.randomBytes(8).toString('hex');
    // Assuming your OAuth authorize endpoint is /oauth/authorize
    const authorizeUrl = `/oauth/authorize?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&response_type=code&state=${state}`;
    res.redirect(authorizeUrl);
});

// OAuth callback handler
app.get('/demoClient/callback', async (req, res) => {
    const { code, state } = req.query;
    if (!code) {
        return res.status(400).send('Missing code');
    }
    // Simulate exchanging code for access token using test client credentials
    // In a real app, you'd POST to /oauth/token with client_id, client_secret, code, and redirect_uri
    // For demo, just store code and client info in session
    req.session.demoAuthCode = code;
    req.session.demoClientId = 'masterkey';
    req.session.demoClientSecret = 'mastersecret';
    res.redirect('/demoClient/main.html');
});

// Demo client user info API
app.get('/demoClient/api/user', (req, res) => {
    // For demo, check if code and client credentials are in session
    if (!req.session.demoAuthCode || req.session.demoClientId !== 'masterkey' || req.session.demoClientSecret !== 'mastersecret') {
        return res.status(401).json({ message: 'Not authenticated' });
    }
    // In real case, lookup user by code or access token
    // Here, return mock user data
    res.json({
        userId: 'demoUser',
        name: 'Demo User',
        email: 'demo@example.com'
    });
});

// Demo client logout
app.post('/demoClient/logout', (req, res) => {
    delete req.session.demoAuthCode;
    delete req.session.demoClientId;
    delete req.session.demoClientSecret;
    res.json({ message: 'Logged out' });
});

app.get("/ping", (req,res)=>{
    console.log("wefi;jewoifwejoi")
    res.send("wefwefe")
})

app.listen("3000", ()=>{
    console.log('gogogisng 3000');
})