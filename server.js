// --- 基本部品の読み込み ---
require('dotenv').config();
const express = require('express');
const path = require('path');
const multer = require('multer');
const multerS3 = require('multer-s3');
const { S3Client, DeleteObjectsCommand, CopyObjectCommand, DeleteObjectCommand: S3DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { Pool } = require('pg');
// --- ▼ 認証機能ここから ▼ ---
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const PgStore = require('connect-pg-simple')(session); // DBにセッションを保存
// --- ▲ 認証機能ここまで ▲ ---
const { createWorker } = require('tesseract.js'); // OCR
const sharp = require('sharp'); // 画像処理
const https = require('https'); // 画像URL取得

const app = express();
const port = process.env.PORT || 3000;

// --- 1. データベース (PostgreSQL) 接続 ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Render
});

// --- Middleware 設定 ---
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// --- ▼ 認証機能ここから (Session と Passport の設定) ▼ ---

// セッションの設定
app.use(session({
    store: new PgStore({
        pool: pool,                // 既存のDB接続プール
        tableName: 'user_sessions' // セッションを保存するテーブル名
    }),
    secret: process.env.SESSION_SECRET, // .env ファイルに SESSION_SECRET=... を追加してください
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30日間
        secure: process.env.NODE_ENV === 'production', // 本番環境では true
        httpOnly: true 
    } 
}));

// Passport の初期化
app.use(passport.initialize());
app.use(passport.session());

// Passport: ログイン戦略 (LocalStrategy) の定義
passport.use(new LocalStrategy(
    async (username, password, done) => {
        try {
            const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
            if (rows.length === 0) {
                // ユーザーが存在しない
                return done(null, false, { message: 'ユーザー名またはパスワードが違います。' });
            }
            const user = rows[0];
            // パスワードを比較
            const isMatch = await bcrypt.compare(password, user.password_hash);
            if (isMatch) {
                // 認証成功
                return done(null, user);
            } else {
                // パスワード不一致
                return done(null, false, { message: 'ユーザー名またはパスワードが違います。' });
            }
        } catch (error) {
            return done(error);
        }
    }
));

// Passport: セッションにユーザー情報を保存 (IDのみ)
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Passport: セッションからユーザー情報を復元
passport.deserializeUser(async (id, done) => {
    try {
        const { rows } = await pool.query('SELECT id, username FROM users WHERE id = $1', [id]);
        if (rows.length > 0) {
            done(null, rows[0]);
        } else {
            done(new Error('User not found'));
        }
    } catch (error) {
        done(error);
    }
});

// ログイン状態をチェックするミドルウェア (番人)
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next(); // ログイン済み -> 次の処理へ
    }
    // 未ログイン -> 401エラーを返す
    res.status(401).json({ message: 'ログインが必要です。' });
}
// --- ▲ 認証機能ここまで ▲ ---


// --- DBテーブル自動作成関数 (▼ 修正 ▼) ---
const createTable = async () => {
    const createImagesTable = `
    CREATE TABLE IF NOT EXISTS images (
      id SERIAL PRIMARY KEY, title VARCHAR(255) NOT NULL, url VARCHAR(1024) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      category_1 VARCHAR(100) DEFAULT 'default_cat1',
      category_2 VARCHAR(100) DEFAULT 'default_cat2',
      category_3 VARCHAR(100) DEFAULT 'default_cat3',
      folder_name VARCHAR(100) DEFAULT 'default_folder'
    );`;

    // --- ▼ 認証機能ここから (テーブル追加) ▼ ---
    const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password_hash VARCHAR(100) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`;

    // connect-pg-simple が要求するセッションテーブル
    const createSessionTable = `
    CREATE TABLE IF NOT EXISTS "user_sessions" (
      "sid" varchar NOT NULL COLLATE "default",
      "sess" json NOT NULL,
      "expire" timestamp(6) NOT NULL
    ) WITH (OIDS=FALSE);
    ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE;
    CREATE INDEX IF NOT EXISTS "IDX_user_sessions_expire" ON "user_sessions" ("expire");
    `;
    // --- ▲ 認証機能ここまで ▲ ---
    
    const alterColumns = [ /* (変更なし) */ ];
    const createIndexes = [ /* (変更なし) */ ];

    try {
        await pool.query(createImagesTable);
        // --- ▼ 認証機能ここから (テーブル作成実行) ▼ ---
        await pool.query(createUsersTable);
        await pool.query(createSessionTable);
        // --- ▲ 認証機能ここまで ▲ ---
        
        for (const query of alterColumns) { await pool.query(query); }
        console.log('Database tables altered.');
        for (const query of createIndexes) { await pool.query(query); }
        console.log('Database indexes created.');
        console.log('Database tables ready.');
    } catch (err) { console.error('DB init error:', err); }
};

// --- ストレージ (R2) 接続 (変更なし) ---
// ( ... 省略 ... )
const r2Endpoint = `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
const r2PublicUrl = process.env.R2_PUBLIC_URL;
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME;
const s3Client = new S3Client({
    region: 'auto', endpoint: r2Endpoint,
    credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY },
});

// --- Multer (アップロード処理) 設定 (変更なし) ---
// ( ... 省略 ... )
const upload = multer({
    storage: multerS3({
        s3: s3Client, bucket: R2_BUCKET_NAME, acl: 'public-read',
        key: function (req, file, cb) {
            const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
            cb(null, originalName); // 元のファイル名でアップロード
        },
        contentType: multerS3.AUTO_CONTENT_TYPE
    }),
    fileFilter: (req, file, cb) => { if (file.mimetype.startsWith('image/')) { cb(null, true); } else { cb(new Error('画像のみ'), false); } }
});

// -----------------------------------------------------------------
// ★★★★★ ルート（URL）設定 ★★★★★
// -----------------------------------------------------------------

// --- ▼ 認証機能ここから (認証ルート) ▼ ---

// [GET] ログインページ
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// [GET] 新規登録ページ
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

// [POST] 新規登録 API
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || password.length < 8) {
        return res.status(400).json({ message: 'ユーザー名と8文字以上のパスワードが必要です。' });
    }
    try {
        // パスワードをハッシュ化
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        
        // ユーザーをDBに保存
        await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [username, passwordHash]);
        res.status(201).json({ message: '登録が成功しました。' });

    } catch (error) {
        if (error.code === '23505') { // unique_violation
            res.status(409).json({ message: 'そのユーザー名はすでに使用されています。' });
        } else {
            console.error('Register Error:', error);
            res.status(500).json({ message: 'サーバーエラーが発生しました。' });
        }
    }
});

// [POST] ログイン API
app.post('/api/auth/login', passport.authenticate('local'), (req, res) => {
    // 認証が成功すると、passport.authenticate が req.user を設定する
    res.json({ message: 'ログイン成功', user: req.user.username });
});

// [POST] ログアウト API
app.post('/api/auth/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        req.session.destroy((err) => {
            if (err) {
                 return res.status(500).json({ message: 'ログアウトに失敗しました。' });
            }
            res.clearCookie('connect.sid'); // セッションクッキーを削除
            res.json({ message: 'ログアウトしました。' });
        });
    });
});

// [GET] ログイン状態チェック API
app.get('/api/auth/check', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ loggedIn: true, username: req.user.username });
    } else {
        res.json({ loggedIn: false });
    }
});
// --- ▲ 認証機能ここまで ▲ ---


// ★ メインページ ( / ) - (▼ 修正 ▼ ログイン必須にする)
// メインページ自体は表示させるが、フロント側でログインチェックを行う
app.get('/', (req, res) => { 
    res.sendFile(path.join(__dirname, 'index.html'));
});


// ==================================================================
// ▼▼▼ アップロードAPI (/upload) ▼▼▼
// ==================================================================
// --- ▼ 修正 ▼ ログイン必須ミドルウェア(isAuthenticated)を追加
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => {
    // ( ... 中身は変更なし ... )
    const { category1, category2, category3, folderName } = req.body;
    if (!category1 || !category2 || !category3 || !folderName ) { return res.status(400).json({ message: '全カテゴリ・フォルダ名必須' }); }
    if (!req.files || req.files.length === 0) { return res.status(400).json({ message: 'ファイル未選択' }); }
    const cat1Trimmed = category1.trim(); const cat2Trimmed = category2.trim(); const cat3Trimmed = category3.trim(); const folderNameTrimmed = folderName.trim();
    try {
        const values = []; const params = []; let paramIndex = 1;
        for (const file of req.files) {
            const targetFilename = file.key;
            const targetUrl = `${r2PublicUrl}/${encodeURIComponent(targetFilename)}`;
            values.push(`($${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++})`);
            params.push(targetFilename, targetUrl, cat1Trimmed, cat2Trimmed, cat3Trimmed, folderNameTrimmed);
        }
        const queryText = `
            INSERT INTO images (title, url, category_1, category_2, category_3, folder_name) 
            VALUES ${values.join(', ')}
        `;
        await pool.query(queryText, params);
        res.json({ message: `「${category1}/${category2}/${category3}/${folderName}」に ${req.files.length} 件を元のファイル名で保存しました。` });
    } catch (error) { console.error('[Upload V3] Error during processing:', error); res.status(500).json({ message: 'ファイル処理エラー' }); }
});

// ==================================================================
// ▼▼▼ CSV API (/download-csv) ▼▼▼
// ==================================================================
// --- ▼ 修正 ▼ ログイン必須ミドルウェア(isAuthenticated)を追加
app.get('/download-csv', isAuthenticated, async (req, res) => {
    // ( ... 中身は変更なし ... )
    try {
        const { folder } = req.query; let queryText; let queryParams;
        const orderByClause = 'ORDER BY length(title), title ASC';
        if (folder) { queryText = `SELECT title, url, category_1, category_2, category_3, folder_name FROM images WHERE folder_name = $1 ${orderByClause}`; queryParams = [decodeURIComponent(folder)]; }
        else { queryText = `SELECT title, url, category_1, category_2, category_3, folder_name FROM images ORDER BY category_1, category_2, category_3, folder_name, length(title), title ASC`; queryParams = []; }
        const { rows } = await pool.query(queryText, queryParams); if (rows.length === 0) { return res.status(404).send('対象履歴なし'); }
        let csvContent = "大カテゴリ,中カテゴリ,小カテゴリ,フォルダ名,題名,URL\n";
        rows.forEach(item => { const c1=`"${(item.category_1||'').replace(/"/g,'""')}"`; const c2=`"${(item.category_2||'').replace(/"/g,'""')}"`; const c3=`"${(item.category_3||'').replace(/"/g,'""')}"`; const f=`"${(item.folder_name||'').replace(/"/g,'""')}"`; const titleWithoutExtension = item.title.substring(0, item.title.lastIndexOf('.')) || item.title; const t = `"${titleWithoutExtension.replace(/"/g,'""')}"`; const u=`"${item.url.replace(/"/g,'""')}"`; csvContent += `${c1},${c2},${c3},${f},${t},${u}\n`; });
        const fileName = folder ? `list_${decodeURIComponent(folder)}.csv` : 'list_all.csv'; const bom = '\uFEFF'; res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`); res.status(200).send(bom + csvContent);
    } catch (dbError) { console.error('CSV Error:', dbError); res.status(500).send('CSV生成失敗'); }
});


// ==================================================================
// ▼▼▼ ギャラリー・編集・削除 API ▼▼▼
// ==================================================================
// --- ▼ 修正 ▼ すべてのAPIの先頭に isAuthenticated を追加

app.get('/api/cat1', isAuthenticated, async (req, res) => { /* (中身変更なし) */ });
app.get('/api/cat2/:cat1', isAuthenticated, async (req, res) => { /* (中身変更なし) */ });
app.get('/api/cat3/:cat1/:cat2', isAuthenticated, async (req, res) => { /* (中身変更なし) */ });
app.get('/api/folders/:cat1/:cat2/:cat3', isAuthenticated, async (req, res) => { /* (中身変更なし) */ });
app.get('/api/images/:folderName', isAuthenticated, async (req, res) => { /* (中身変更なし) */ });
app.get('/api/search', isAuthenticated, async (req, res) => { /* (中身変更なし) */ });

// --- カテゴリ・フォルダ編集API ---
app.put('/api/cat1/:oldName', isAuthenticated, async (req, res) => { /* (中身変更なし) */ });
app.put('/api/cat2/:cat1/:oldName', isAuthenticated, async (req, res) => { /* (中身変更なし) */ });
app.put('/api/cat3/:cat1/:cat2/:oldName', isAuthenticated, async (req, res) => { /* (中身変更なし) */ });
app.put('/api/folder/:oldName', isAuthenticated, async (req, res) => { /* (中身変更なし) */ });

// --- カテゴリ・フォルダ削除API ---
async function performDelete(res, conditions, params, itemDescription) { /* (中身変更なし) */ }
app.delete('/api/cat1/:name', isAuthenticated, async (req, res) => { /* (中身変更なし) */ });
app.delete('/api/cat2/:cat1/:name', isAuthenticated, async (req, res) => { /* (中身変更なし) */ });
app.delete('/api/cat3/:cat1/:cat2/:name', isAuthenticated, async (req, res) => { /* (中身変更なし) */ });
app.delete('/api/folder/:name', isAuthenticated, async (req, res) => { /* (中身変更なし) */ });

// --- 画像移動API ---
app.put('/api/image/:imageTitle', isAuthenticated, async (req, res) => { /* (中身変更なし) */ });

// --- 解析API (Tesseract.js 版) ---
app.post('/api/analyze/:folderName', isAuthenticated, async (req, res) => { /* (中身変更なし) */ });


// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable();
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});

// (※) /api/cat1 等、中身を省略した部分は元のコードのままでOKです。
//     isAuthenticated を引数に追加するだけです。