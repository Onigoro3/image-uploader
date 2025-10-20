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
const { createWorker } = require('tesseract.js'); // OCR

const app = express();
const port = process.env.PORT || 3000;

// --- 1. データベース (PostgreSQL) 接続 ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// --- テンプレートエンジン(EJS) 設定 ---
app.engine('html', ejs.renderFile);
app.set('view engine', 'html');
app.set('views', __dirname);

// --- Middleware 設定 ---
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(session({
    store: new PgSession({ pool: pool, tableName: 'user_sessions' }),
    secret: process.env.SESSION_SECRET || 'please_set_a_strong_secret_in_env', // Use env var!
    resave: false, // Explicitly set resave
    saveUninitialized: false, // Explicitly set saveUninitialized
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 days
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// --- Passport 設定 ---
passport.use(new LocalStrategy(
    async (username, password, done) => {
        try {
            const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
            if (rows.length === 0) { return done(null, false, { message: 'ユーザー名が見つかりません。' }); }
            const user = rows[0];
            const isMatch = await bcrypt.compare(password, user.password_hash);
            if (isMatch) { return done(null, user); }
            else { return done(null, false, { message: 'パスワードが間違っています。' }); }
        } catch (err) { console.error('Passport Error:', err); return done(err); }
    }
));
passport.serializeUser((user, done) => { done(null, user.id); });
passport.deserializeUser(async (id, done) => {
    try {
        const { rows } = await pool.query('SELECT id, username FROM users WHERE id = $1', [id]);
        if (rows.length > 0) { done(null, rows[0]); } else { done(null, false); }
    } catch (err) { console.error('Deserialize Error:', err); done(err); }
});

// --- DBテーブル自動作成関数 (4階層対応) ---
const createTable = async () => {
    const userQuery = `CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash VARCHAR(100) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`;
    const sessionQuery = `CREATE TABLE IF NOT EXISTS "user_sessions" ("sid" varchar NOT NULL COLLATE "default","sess" json NOT NULL,"expire" timestamp(6) NOT NULL) WITH (OIDS=FALSE); DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'user_sessions_pkey') THEN ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE; END IF; END $$; CREATE INDEX IF NOT EXISTS "IDX_user_sessions_expire" ON "user_sessions" ("expire");`;
    const createQuery = `
    CREATE TABLE IF NOT EXISTS images (
      id SERIAL PRIMARY KEY, title VARCHAR(255) NOT NULL, url VARCHAR(1024) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      category_1 VARCHAR(100) DEFAULT 'default_cat1',
      category_2 VARCHAR(100) DEFAULT 'default_cat2',
      category_3 VARCHAR(100) DEFAULT 'default_cat3',
      folder_name VARCHAR(100) DEFAULT 'default_folder'
    );`;
    const alterColumns = [
        `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_1') THEN ALTER TABLE images ADD COLUMN category_1 VARCHAR(100) DEFAULT 'default_cat1'; END IF; END $$;`,
        `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_2') THEN ALTER TABLE images ADD COLUMN category_2 VARCHAR(100) DEFAULT 'default_cat2'; END IF; END $$;`,
        `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_3') THEN ALTER TABLE images ADD COLUMN category_3 VARCHAR(100) DEFAULT 'default_cat3'; END IF; END $$;`,
        `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='folder_name') THEN ALTER TABLE images ADD COLUMN folder_name VARCHAR(100) DEFAULT 'default_folder'; END IF; END $$;`
    ];
    try {
        await pool.query(userQuery); await pool.query(sessionQuery); await pool.query(createQuery);
        for (const query of alterColumns) { await pool.query(query); }
        console.log('Database tables ready.');
    } catch (err) { console.error('DB init error:', err); }
};

// --- ストレージ (R2) 接続 ---
const r2Endpoint = `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
const r2PublicUrl = process.env.R2_PUBLIC_URL;
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME;
const s3Client = new S3Client({
    region: 'auto', endpoint: r2Endpoint,
    credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY_ID,
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
    },
});

// --- Multer (アップロード処理) 設定 ---
const upload = multer({
    storage: multerS3({
        s3: s3Client,
        bucket: R2_BUCKET_NAME,
        acl: 'public-read',
        key: function (req, file, cb) {
            const decodedFilename = Buffer.from(file.originalname, 'latin1').toString('utf8');
            cb(null, decodedFilename);
        }
    }),
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) { cb(null, true); }
        else { cb(new Error('画像ファイルのみ'), false); }
    }
});

// --- ログインチェック関数 ---
function isAuthenticated(req, res, next) { if (req.isAuthenticated()) { return next(); } res.redirect('/login'); }

// -----------------------------------------------------------------
// ★★★★★ ルート（URL）設定 ★★★★★
// -----------------------------------------------------------------

// --- 認証不要ルート ---
app.get('/login', (req, res) => { res.render('login.html', { messages: req.flash('error') }); });
app.post('/login', passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login', failureFlash: true }));
app.get('/logout', (req, res, next) => { req.logout((err) => { if (err) { return next(err); } res.redirect('/login'); }); });

// --- ログイン必須ルート ---
app.get('/', isAuthenticated, (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

// アップロードAPI (/upload)
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => { /* ... (前のコードと同じ) ... */ });
// CSV API (/download-csv)
app.get('/download-csv', isAuthenticated, async (req, res) => { /* ... (前のコードと同じ) ... */ });
// ギャラリー用API (/api/cat1, /api/cat2/:cat1, etc.)
app.get('/api/cat1', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/cat2/:cat1', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/cat3/:cat1/:cat2', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/folders/:cat1/:cat2/:cat3', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/images/:folderName', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/search', isAuthenticated, async (req, res) => { /* ... */ });
// カテゴリ・フォルダ編集API (PUT /api/cat1/:oldName, etc.)
app.put('/api/cat1/:oldName', isAuthenticated, async (req, res) => { /* ... */ });
app.put('/api/cat2/:cat1/:oldName', isAuthenticated, async (req, res) => { /* ... */ });
app.put('/api/cat3/:cat1/:cat2/:oldName', isAuthenticated, async (req, res) => { /* ... */ });
app.put('/api/folder/:oldName', isAuthenticated, async (req, res) => { /* ... */ });
// カテゴリ・フォルダ削除API (DELETE /api/cat1/:name, etc.)
async function performDelete(res, conditions, params, itemDescription) { /* ... (前のコードと同じ) ... */ }
app.delete('/api/cat1/:name', isAuthenticated, async (req, res) => { await performDelete(res, 'category_1 = $1', [req.params.name], `大カテゴリ「${req.params.name}」`); });
app.delete('/api/cat2/:cat1/:name', isAuthenticated, async (req, res) => { await performDelete(res, 'category_1 = $1 AND category_2 = $2', [req.params.cat1, req.params.name], `中カテゴリ「${req.params.name}」`); });
app.delete('/api/cat3/:cat1/:cat2/:name', isAuthenticated, async (req, res) => { await performDelete(res, 'category_1 = $1 AND category_2 = $2 AND category_3 = $3', [req.params.cat1, req.params.cat2, req.params.name], `小カテゴリ「${req.params.name}」`); });
app.delete('/api/folder/:name', isAuthenticated, async (req, res) => { await performDelete(res, 'folder_name = $1', [req.params.name], `フォルダ「${req.params.name}」`); });

// ▼▼▼ 解析API (/api/analyze/:folderName) ▼▼▼
app.post('/api/analyze/:folderName', isAuthenticated, async (req, res) => {
    const { folderName } = req.params;
    console.log(`[Analyze] Req: ${folderName}`);
    let worker;
    try {
        const { rows } = await pool.query('SELECT title, url FROM images WHERE folder_name = $1 ORDER BY title', [folderName]);
        if (rows.length === 0) return res.status(404).json({ message: '画像なし' });
        console.log(`[Analyze] Found ${rows.length} images`);
        worker = await createWorker('jpn+eng', 1, { logger: m => console.log(`[Tesseract] ${m.status}: ${m.progress * 100}%`) });
        console.log('[Analyze] Worker init.');
        let analysisResults = [];
        for (const image of rows) {
            console.log(`[Analyze] OCR: ${image.title}`);
            try {
                 const { data: { text } } = await worker.recognize(image.url);
                 analysisResults.push({ filename: image.title, recognizedText: text.replace(/"/g, '""').replace(/\n/g, ' ') }); // Escape quotes and newlines
            } catch (ocrError) { analysisResults.push({ filename: image.title, recognizedText: '*** OCRエラー ***' }); }
        }
        await worker.terminate(); worker = null; console.log('[Analyze] Worker terminated.');
        let csvContent = "ファイル名,認識テキスト\n";
        analysisResults.forEach(r => { csvContent += `"${r.filename}","${r.recognizedText}"\n`; });
        const fileName = `analysis_${folderName}.csv`;
        const bom = '\uFEFF';
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`);
        res.status(200).send(bom + csvContent); console.log(`[Analyze] Sent CSV`);
    } catch (error) {
        console.error(`[Analyze] Error:`, error);
        if (worker) { try { await worker.terminate(); } catch (e) { console.error('Error terminating worker:', e);} }
        res.status(500).json({ message: '解析エラー' });
    }
});

// ▼▼▼ 画像移動API (/api/image/:imageTitle) ▼▼▼
app.put('/api/image/:imageTitle', isAuthenticated, async (req, res) => {
    const { imageTitle } = req.params;
    const { category1, category2, category3, folderName } = req.body;
    if (!category1 || !category2 || !category3 || !folderName) { return res.status(400).json({ message: '移動先指定必須' }); }
    try {
        const updateQuery = `UPDATE images SET category_1 = $1, category_2 = $2, category_3 = $3, folder_name = $4 WHERE title = $5`;
        const result = await pool.query(updateQuery, [ category1.trim(), category2.trim(), category3.trim(), folderName.trim(), imageTitle ]);
        if (result.rowCount === 0) { return res.status(404).json({ message: '画像なし' }); }
        res.json({ message: `画像移動完了` });
    } catch (error) { console.error(`Move Image Error:`, error); res.status(500).json({ message: '移動失敗' }); }
});

// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable();
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});

// --- 省略した関数の補足 ---
// pool, session, passport use/serialize/deserialize, createTable, s3Client, upload, isAuthenticated
// 各API (/login, /logout, /, /upload, /download-csv, /api/cat*, /api/folders*, /api/images*, /api/search, PUT/DELETE /api/*) の基本ロジックは前のコードと同じ