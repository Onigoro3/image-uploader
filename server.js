// --- 基本部品の読み込み ---
require('dotenv').config();
const express = require('express');
const path = require('path');
const multer = require('multer');
const multerS3 = require('multer-s3');
const { S3Client, DeleteObjectsCommand } = require('@aws-sdk/client-s3');
const { Pool } = require('pg');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const PgSession = require('connect-pg-simple')(session);
const flash = require('connect-flash');
const ejs = require('ejs');
const { createWorker } = require('tesseract.js'); // ★ Tesseract.js
const sharp = require('sharp'); // ★ 画像処理
const https = require('https'); // ★ 画像URL取得

const app = express();
const port = process.env.PORT || 3000;

// --- DB接続, Middleware, Passport, DBテーブル作成 (変更なし) ---
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
app.engine('html', ejs.renderFile); app.set('view engine', 'html'); app.set('views', __dirname);
app.use(express.json()); app.use(express.urlencoded({ extended: false }));
app.use(session({ store: new PgSession({ pool: pool, tableName: 'user_sessions' }), secret: process.env.SESSION_SECRET || 'fallback_secret_set_in_env_variable', resave: false, saveUninitialized: false, cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'lax' } }));
app.use(flash()); app.use(passport.initialize()); app.use(passport.session());
passport.use(new LocalStrategy( async (username, password, done) => { try { const r = await pool.query('SELECT * FROM users WHERE username = $1', [username]); if (r.rows.length === 0) { return done(null, false, { message: 'ユーザー名なし' }); } const user = r.rows[0]; const i = await bcrypt.compare(password, user.password_hash); if (i) { return done(null, user); } else { return done(null, false, { message: 'パスワード違い' }); } } catch (e) { console.error(e); return done(e); } } ));
passport.serializeUser((user, done) => { done(null, user.id); });
passport.deserializeUser(async (id, done) => { try { const r = await pool.query('SELECT id, username FROM users WHERE id = $1', [id]); if (r.rows.length > 0) { done(null, r.rows[0]); } else { done(null, false); } } catch (e) { console.error(e); done(e); } });
const createTable = async () => { const uQ=`...`; const sQ=`...`; const cQ=`...`; const aCs=[`...`,`...`,`...`,`...`]; try { await pool.query(uQ); await pool.query(sQ); await pool.query(cQ); for(const q of aCs){await pool.query(q);} console.log('DB tables ready.'); } catch(e){ console.error('DB init err:',e); } }; // (DBスキーマは変更なし)

// --- R2接続, Multer設定 (変更なし) ---
const r2Endpoint = `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`; const r2PublicUrl = process.env.R2_PUBLIC_URL; const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME;
const s3Client = new S3Client({ region: 'auto', endpoint: r2Endpoint, credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY } });
const upload = multer({ storage: multerS3({ s3: s3Client, bucket: R2_BUCKET_NAME, acl: 'public-read', key: (req, f, cb) => { const d = Buffer.from(f.originalname, 'latin1').toString('utf8'); cb(null, d); } }), fileFilter: (req, f, cb) => { if (f.mimetype.startsWith('image/')) { cb(null, true); } else { cb(new Error('画像のみ'), false); } } });

// --- ログインチェック関数 (変更なし) ---
function isAuthenticated(req, res, next) { if (req.isAuthenticated()) { return next(); } res.redirect('/login'); }

// -----------------------------------------------------------------
// ★★★★★ ルート（URL）設定 ★★★★★
// -----------------------------------------------------------------

// --- 認証不要・ログイン必須の基本ルート (変更なし) ---
app.get('/login', (req, res) => { res.render('login.html', { messages: req.flash('error') }); });
app.post('/login', passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login', failureFlash: true }));
app.get('/logout', (req, res, next) => { req.logout((err) => { if (err) { return next(err); } res.redirect('/login'); }); });
app.get('/', isAuthenticated, (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => { /* ... (変更なし) ... */ });
app.get('/download-csv', isAuthenticated, async (req, res) => { /* ... (変更なし) ... */ });
// --- ギャラリー用API (変更なし) ---
app.get('/api/cat1', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/cat2/:cat1', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/cat3/:cat1/:cat2', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/folders/:cat1/:cat2/:cat3', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/images/:folderName', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/search', isAuthenticated, async (req, res) => { /* ... */ });
// --- カテゴリ・フォルダ編集API (変更なし) ---
app.put('/api/cat1/:oldName', isAuthenticated, async (req, res) => { /* ... */ }); /* ... (PUT /api/cat2, /api/cat3, /api/folder) ... */
async function performDelete(res, conditions, params, itemDescription) { /* ... */ }
app.delete('/api/cat1/:name', isAuthenticated, async (req, res) => { /* ... */ }); /* ... (DELETE /api/cat2, /api/cat3, /api/folder) ... */
// --- 画像移動API (変更なし) ---
app.put('/api/image/:imageTitle', isAuthenticated, async (req, res) => { /* ... */ });

// ▼▼▼【Tesseract.js 版】フォルダ解析API (/api/analyze/:folderName) ▼▼▼
app.post('/api/analyze/:folderName', isAuthenticated, async (req, res) => {
    const { folderName } = req.params;
    console.log(`[Analyze Tesseract] Req: ${folderName}`);
    let worker;
    const getImageBuffer = (url) => new Promise((resolve, reject) => { https.get(url, (response) => { if (response.statusCode !== 200) return reject(new Error(`Status Code: ${response.statusCode}`)); const d = []; response.on('data', c => d.push(c)); response.on('end', () => resolve(Buffer.concat(d))); }).on('error', reject); });
    const runOCR = async (buffer, regionName) => { try { const pBuf = await sharp(buffer).grayscale().toBuffer(); const { data: { text } } = await worker.recognize(pBuf); console.log(`[Tesseract] OCR Ok [${regionName}]`); return text.replace(/"/g, '""').replace(/\n/g, ' ').trim(); } catch (e) { console.error(`[Tesseract] OCR Err [${regionName}]:`, e.message); return '*** OCR ERR ***'; } };
    try {
        const { rows } = await pool.query('SELECT title, url FROM images WHERE folder_name = $1 ORDER BY title', [folderName]); if (rows.length === 0) return res.status(404).json({ message: '画像なし' });
        console.log(`[Tesseract] Found ${rows.length} images`);
        worker = await createWorker('jpn+eng', 1, { logger: m => console.log(`[Tesseract] ${m.status}: ${m.progress * 100}%`) }); console.log('[Tesseract] Worker init.');
        let analysisResults = [];
        for (const image of rows) {
            console.log(`[Tesseract] Processing: ${image.title}`); const result = { filename: image.title, cardName: '', cardText: '', power: '', cost: '', expansion: '' };
            try {
                const imageBuffer = await getImageBuffer(image.url); const metadata = await sharp(imageBuffer).metadata(); const w = metadata.width; const h = metadata.height;
                const regions = { cardName: { left: Math.round(w * 0.1), top: Math.round(h * 0.05), width: Math.round(w * 0.8), height: Math.round(h * 0.08) }, cost: { left: Math.round(w * 0.03), top: Math.round(h * 0.03), width: Math.round(w * 0.1), height: Math.round(h * 0.08) }, cardText: { left: Math.round(w * 0.1), top: Math.round(h * 0.55), width: Math.round(w * 0.8), height: Math.round(h * 0.3) }, power: { left: Math.round(w * 0.05), top: Math.round(h * 0.88), width: Math.round(w * 0.25), height: Math.round(h * 0.08) }, expansion:{ left: Math.round(w * 0.65), top: Math.round(h * 0.88), width: Math.round(w * 0.25), height: Math.round(h * 0.05) }, };
                if (regions.cardName) result.cardName = await runOCR(await sharp(imageBuffer).extract(regions.cardName).toBuffer(), 'Name');
                if (regions.cost) result.cost = await runOCR(await sharp(imageBuffer).extract(regions.cost).toBuffer(), 'Cost');
                if (regions.cardText) result.cardText = await runOCR(await sharp(imageBuffer).extract(regions.cardText).toBuffer(), 'Text');
                if (regions.power) result.power = await runOCR(await sharp(imageBuffer).extract(regions.power).toBuffer(), 'Power');
                if (regions.expansion) result.expansion = await runOCR(await sharp(imageBuffer).extract(regions.expansion).toBuffer(), 'Expansion');
                analysisResults.push(result); console.log(`[Tesseract] Processed ${image.title}`);
            } catch (imgError) { console.error(`[Tesseract] Image Err ${image.title}:`, imgError.message); analysisResults.push({ ...result, cardName: '*** IMG ERR ***' }); }
        }
        await worker.terminate(); worker = null; console.log('[Tesseract] Worker terminated.');
        let csvContent = "ファイル名,カード名,コスト,テキスト,パワー,エキスパンション\n"; analysisResults.forEach(r => { csvContent += `"${r.filename}","${r.cardName}","${r.cost}","${r.cardText}","${r.power}","${r.expansion}"\n`; });
        const fileName = `analysis_tesseract_${folderName}.csv`; const bom = '\uFEFF'; res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`); res.status(200).send(bom + csvContent); console.log(`[Tesseract] Sent CSV`);
    } catch (error) { console.error(`[Tesseract] Error:`, error); if (worker) { try { await worker.terminate(); } catch (e) { console.error('Error terminating worker:', e);} } res.status(500).json({ message: '解析エラー発生' }); }
});
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable();
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});

// --- 省略した関数の補足 ---
// pool, session, passport use/serialize/deserialize, createTable, s3Client, upload, isAuthenticated
// 基本的なAPI (/login, /logout, /, /upload, /download-csv(通常版), /api/cat*, /api/folders*, /api/images*, /api/search, PUT/DELETE /api/*)
// の基本ロジックは前のコードと同じ