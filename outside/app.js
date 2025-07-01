const express = require('express');
const session = require('express-session');
const axios = require('axios');
const app = express();
const port = 3333;

// const OAUTH_DOMAIN = "https://nyangoauth.r-e.kr"
const OAUTH_DOMAIN = "http://localhost:3000"
const CLIENT_ID = "6d4741ae-1156-4f2c-b9b8-fde7c737eee4"
const CLEINT_SECRET = "VobpjpZQGf04Iye/jVZln1SoM9j3zDcvMDBVJ9dnxvg="
const REDIRECT_URI = "http://localhost:3333/rd"
// y8rb88tj50c4atu2qpapgsxxg08ewams 복사
// Client Secret
// lp*{1D,,w4MIVFc%#]1VESxHh(oEQNxswICyu;X;sf7r@:=Q+2?J^xTGkSSM?Xi8 복사

const path = require('path')
// 세션 설정
app.use(session({
    secret: 'outside-service-secret',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24시간
}));

// 정적 파일 제공
app.use(express.static(path.join(__dirname, 'public')));

// 메인 페이지
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

// OAuth 인증 시작
app.get('/auth', (req, res) => {
    // const redirectUri = 'http://localhost:3333/rd';
    const authUrl = `${OAUTH_DOMAIN}/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code`;
    // const authUrl = `${OAUTH_DOMAIN}/oauth/authorize?client_id=${CLIENT_ID}`;
    console.log("🚀 ~ app.get ~ authUrl:", authUrl)
    res.redirect(authUrl);
});

// OAuth 인증 콜백 처리
app.get('/rd', async (req, res) => {
    const { code } = req.query;
    if (!code) {
        return res.redirect('/');
    }

    try {
        // 액세스 토큰 요청
        const tokenResponse = await axios.post(`${OAUTH_DOMAIN}/oauth/token`, {
            client_id: CLIENT_ID,
            client_secret: CLEINT_SECRET,
            code: code,
            redirect_uri: 'http://localhost:3333/rd',
            grant_type: 'authorization_code'
        });
        console.log(111, tokenResponse);
        

        // 사용자 정보 요청
        const userResponse = await axios.get(`${OAUTH_DOMAIN}/oauth/userinfo`, {
            headers: {
                'Authorization': `Bearer ${tokenResponse.data.access_token}`
            }
        });
        console.log(222, userResponse);

        // 세션에 사용자 정보 저장
        req.session.user = userResponse.data;
        res.redirect('/dashboard');
    } catch (error) {
        console.error('OAuth 에러:', error.response?.data || error.message);
        // res.redirect('/?error=' + encodeURIComponent(error.response?.data?.error || error.message));
        res.send(`OAuth 에러 뭐안됨: ${error.response?.data?.error || error.message}`);
    }
});

// 사용자 정보 API
app.get('/api/user', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: '로그인이 필요합니다.' });
    }
    res.json(req.session.user);
});

// 대시보드
app.get('/dashboard', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }
    res.sendFile(__dirname + '/public/dashboard.html');
});

// 로그아웃
app.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: '로그아웃되었습니다.' });
});

app.listen(port, () => {
    console.log(`외부 서비스가 http://localhost:${port} 에서 실행 중입니다.`);
});
