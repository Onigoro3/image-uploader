// --- 基本部品の読み込み ---
require('dotenv').config();
const express = require('express');
const path = require('path');
const multer = require('multer');
const multerS3 = require('multer-s3');
const { S3Client, DeleteObjectsCommand, CopyObjectCommand, DeleteObjectCommand: S3DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { Pool } = require('pg');
// --- ▼ 認証関連のライブラリ ▼ ---
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const PgStore = require('connect-pg-simple')(session); // DBにセッションを保存
// --- ▲ 認証関連のライブラリ ▲ ---
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
    // --- ▼▼▼ ログインループ対策の修正箇所 ▼▼▼ ---
    proxy: true, // Render/Herokuなどのリバースプロキシ環境下で必要
    cookie: { 
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30日間
        secure: 'auto', // 'auto' に変更 (http/https 両対応)
        httpOnly: true,
        sameSite: 'lax' // クロスサイトリクエスト対策
    } 
    // --- ▲▲▲ ログインループ対策の修正箇所 ▲▲▲ ---
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
    
    const alterColumns = [
        `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_1') THEN ALTER TABLE images ADD COLUMN category_1 VARCHAR(100) DEFAULT 'default_cat1'; END IF; END $$;`,
        `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_2') THEN ALTER TABLE images ADD COLUMN category_2 VARCHAR(100) DEFAULT 'default_cat2'; END IF; END $$;`,
        `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_3') THEN ALTER TABLE images ADD COLUMN category_3 VARCHAR(100) DEFAULT 'default_cat3'; END IF; END $$;`,
        `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='folder_name') THEN ALTER TABLE images ADD COLUMN folder_name VARCHAR(100) DEFAULT 'default_folder'; END IF; END $$;`
    ];
    // 索引(INDEX)を作成するクエリ
    const createIndexes = [
        `CREATE INDEX IF NOT EXISTS idx_images_cat1 ON images (category_1);`,
        `CREATE INDEX IF NOT EXISTS idx_images_cat1_cat2 ON images (category_1, category_2);`,
        `CREATE INDEX IF NOT EXISTS idx_images_cat1_cat2_cat3 ON images (category_1, category_2, category_3);`,
        `CREATE INDEX IF NOT EXISTS idx_images_folder_name ON images (folder_name);`,
        `CREATE INDEX IF NOT EXISTS idx_images_title_length_and_title ON images (length(title), title);`
    ];

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

// --- ストレージ (R2) 接続 ---
const r2Endpoint = `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
const r2PublicUrl = process.env.R2_PUBLIC_URL;
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME;
const s3Client = new S3Client({
    region: 'auto', endpoint: r2Endpoint,
    credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY },
});

// --- Multer (アップロード処理) 設定 ---
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


// ★ メインページ ( / )
app.get('/', (req, res) => { 
    res.sendFile(path.join(__dirname, 'index.html'));
});


// ==================================================================
// ▼▼▼ アップロードAPI (/upload) ▼▼▼
// ==================================================================
// --- ▼ ログイン必須ミドルウェア(isAuthenticated)を追加
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => {
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
// --- ▼ ログイン必須ミドルウェア(isAuthenticated)を追加
app.get('/download-csv', isAuthenticated, async (req, res) => {
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
// --- ▼ すべてのAPIの先頭に isAuthenticated を追加

app.get('/api/cat1', isAuthenticated, async (req, res) => {
    try {
        console.log("[API] GET /api/cat1 received");
        const query = 'SELECT DISTINCT category_1 FROM images ORDER BY category_1';
        const { rows } = await pool.query(query);
        console.log(`[API] /api/cat1 found ${rows.length} items`);
        res.json(rows.map(r => r.category_1));
    } catch (e) { console.error("!!!!! API /api/cat1 FAILED !!!!!", e); res.status(500).json({ message: 'Error fetching cat1' }); }
});
app.get('/api/cat2/:cat1', isAuthenticated, async (req, res) => { try { console.log(`[API] /api/cat2/${req.params.cat1} received`); const { rows } = await pool.query('SELECT DISTINCT category_2 FROM images WHERE category_1 = $1 ORDER BY category_2', [req.params.cat1]); console.log(`[API] /api/cat2 found ${rows.length}`); res.json(rows.map(r => r.category_2)); } catch (e) { console.error("!!!!! API /api/cat2 FAILED !!!!!", e); res.status(500).json({ message: 'Error fetching cat2' }); } });
app.get('/api/cat3/:cat1/:cat2', isAuthenticated, async (req, res) => { try { console.log(`[API] /api/cat3/${req.params.cat1}/${req.params.cat2} received`); const { rows } = await pool.query('SELECT DISTINCT category_3 FROM images WHERE category_1 = $1 AND category_2 = $2 ORDER BY category_3', [req.params.cat1, req.params.cat2]); console.log(`[API] /api/cat3 found ${rows.length}`); res.json(rows.map(r => r.category_3)); } catch (e) { console.error("!!!!! API /api/cat3 FAILED !!!!!", e); res.status(500).json({ message: 'Error fetching cat3' }); } });
app.get('/api/folders/:cat1/:cat2/:cat3', isAuthenticated, async (req, res) => { try { console.log(`[API] /api/folders received`); const { rows } = await pool.query('SELECT DISTINCT folder_name FROM images WHERE category_1 = $1 AND category_2 = $2 AND category_3 = $3 ORDER BY folder_name', [req.params.cat1, req.params.cat2, req.params.cat3]); console.log(`[API] /api/folders found ${rows.length}`); res.json(rows.map(r => r.folder_name)); } catch (e) { console.error("!!!!! API /api/folders FAILED !!!!!", e); res.status(500).json({ message: 'Error fetching folders' }); } });
app.get('/api/images/:folderName', isAuthenticated, async (req, res) => { try { console.log(`[API] /api/images/${req.params.folderName} received`); const sortBy = req.query.sort === 'title' ? 'title' : 'created_at'; const sortOrder = req.query.order === 'ASC' ? 'ASC' : 'DESC'; const qT = `SELECT title, url FROM images WHERE folder_name = $1 ORDER BY ${sortBy} ${sortOrder}, id ${sortOrder}`; const { rows } = await pool.query(qT, [req.params.folderName]); console.log(`[API] /api/images found ${rows.length}`); res.json(rows); } catch (e) { console.error("!!!!! API /api/images FAILED !!!!!", e); res.status(500).json({ message: 'Error fetching images' }); } });
app.get('/api/search', isAuthenticated, async (req, res) => { const { folder, q } = req.query; console.log(`[API] /api/search received (folder: ${folder}, q: ${q})`); const sortBy = req.query.sort === 'title' ? 'title' : 'created_at'; const sortOrder = req.query.order === 'ASC' ? 'ASC' : 'DESC'; if (!folder) { return res.status(400).json({ message: 'フォルダ指定必須' }); } try { let qT; let qP; const oBC = `ORDER BY ${sortBy} ${sortOrder}, id ${sortOrder}`; if (q && q.trim() !== '') { const s = `%${q}%`; qT = `SELECT title, url FROM images WHERE folder_name = $1 AND title ILIKE $2 ${oBC}`; qP = [folder, s]; } else { qT = `SELECT title, url FROM images WHERE folder_name = $1 ${oBC}`; qP = [folder]; } const { rows } = await pool.query(qT, qP); console.log(`[API] /api/search found ${rows.length}`); res.json(rows); } catch (e) { console.error("!!!!! API /api/search FAILED !!!!!", e); res.status(500).json({ message: '検索失敗' }); } });

// --- カテゴリ・フォルダ編集API ---
app.put('/api/cat1/:oldName', isAuthenticated, async (req, res) => { const { oldName } = req.params; const { newName } = req.body; if (!newName || newName.trim() === '' || newName.trim() === oldName) return res.status(400).json({message: 'Invalid name'}); try { await pool.query('UPDATE images SET category_1 = $1 WHERE category_1 = $2', [newName.trim(), oldName]); res.json({ message: `大カテゴリ名変更完了` }); } catch (e) { console.error("Rename Cat1 Error:", e); res.status(500).json({ message: '名前変更失敗' }); } });
app.put('/api/cat2/:cat1/:oldName', isAuthenticated, async (req, res) => { const { cat1, oldName } = req.params; const { newName } = req.body; if (!newName || newName.trim() === '' || newName.trim() === oldName) return res.status(400).json({message: 'Invalid name'}); try { await pool.query('UPDATE images SET category_2 = $1 WHERE category_1 = $2 AND category_2 = $3', [newName.trim(), cat1, oldName]); res.json({ message: `中カテゴリ名変更完了` }); } catch (e) { console.error("Rename Cat2 Error:", e); res.status(500).json({ message: '名前変更失敗' }); } });
app.put('/api/cat3/:cat1/:cat2/:oldName', isAuthenticated, async (req, res) => { const { cat1, cat2, oldName } = req.params; const { newName } = req.body; if (!newName || newName.trim() === '' || newName.trim() === oldName) return res.status(400).json({message: 'Invalid name'}); try { await pool.query('UPDATE images SET category_3 = $1 WHERE category_1 = $2 AND category_2 = $3 AND category_3 = $4', [newName.trim(), cat1, cat2, oldName]); res.json({ message: `小カテゴリ名変更完了` }); } catch (e) { console.error("Rename Cat3 Error:", e); res.status(500).json({ message: '名前変更失敗' }); } });
app.put('/api/folder/:oldName', isAuthenticated, async (req, res) => { const { oldName } = req.params; const { newName } = req.body; if (!newName || newName.trim() === '' || newName.trim() === oldName) return res.status(400).json({message: 'Invalid name'}); try { await pool.query('UPDATE images SET folder_name = $1 WHERE folder_name = $2', [newName.trim(), oldName]); res.json({ message: `フォルダ名変更完了` }); } catch (e) { console.error("Rename Folder Error:", e); res.status(500).json({ message: '名前変更失敗' }); } });

// --- カテゴリ・フォルダ削除API ---
async function performDelete(res, conditions, params, itemDescription) {
    try {
        const { rows } = await pool.query(`SELECT title FROM images WHERE ${conditions}`, params);
        if (rows.length > 0) {
            const objectsToDelete = rows.map(row => ({ Key: row.title }));
            for (let i = 0; i < objectsToDelete.length; i += 1000) { const chunk = objectsToDelete.slice(i, i + 1000); const deleteCommand = new DeleteObjectsCommand({ Bucket: R2_BUCKET_NAME, Delete: { Objects: chunk } }); await s3Client.send(deleteCommand); console.log(`Deleted ${chunk.length} R2 objects`); }
        }
        const deleteResult = await pool.query(`DELETE FROM images WHERE ${conditions}`, params); console.log(`Deleted ${deleteResult.rowCount} DB records for ${itemDescription}`);
        res.json({ message: `${itemDescription} 削除完了` });
    } catch (error) { console.error(`Delete Error:`, error); res.status(500).json({ message: '削除失敗' }); }
}
app.delete('/api/cat1/:name', isAuthenticated, async (req, res) => { await performDelete(res, 'category_1 = $1', [req.params.name], `大カテゴリ「${req.params.name}」`); });
app.delete('/api/cat2/:cat1/:name', isAuthenticated, async (req, res) => { await performDelete(res, 'category_1 = $1 AND category_2 = $2', [req.params.cat1, req.params.name], `中カテゴリ「${req.params.name}」`); });
app.delete('/api/cat3/:cat1/:cat2/:name', isAuthenticated, async (req, res) => { await performDelete(res, 'category_1 = $1 AND category_2 = $2 AND category_3 = $3', [req.params.cat1, req.params.cat2, req.params.name], `小カテゴリ「${req.params.name}」`); });
app.delete('/api/folder/:name', isAuthenticated, async (req, res) => { await performDelete(res, 'folder_name = $1', [req.params.name], `フォルダ「${req.params.name}」`); });

// --- 画像移動API ---
app.put('/api/image/:imageTitle', isAuthenticated, async (req, res) => {
    const { imageTitle } = req.params; const { category1, category2, category3, folderName } = req.body;
    if (!category1 || !category2 || !category3 || !folderName) { return res.status(400).json({ message: '移動先指定必須' }); }
    try {
        const updateQuery = `UPDATE images SET category_1 = $1, category_2 = $2, category_3 = $3, folder_name = $4 WHERE title = $5`;
        const result = await pool.query(updateQuery, [ category1.trim(), category2.trim(), category3.trim(), folderName.trim(), imageTitle ]);
        if (result.rowCount === 0) { return res.status(404).json({ message: '画像なし' }); }
        res.json({ message: `画像移動完了` });
    } catch (error) { console.error(`Move Image Error:`, error); res.status(500).json({ message: '移動失敗' }); }
});

// --- 解析API (Tesseract.js 版) ---
app.post('/api/analyze/:folderName', isAuthenticated, async (req, res) => {
    const { folderName } = req.params; console.log(`[Analyze Tesseract] Req: ${folderName}`); let worker;
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

// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable();
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});