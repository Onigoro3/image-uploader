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
app.use(session({
    store: new PgStore({ pool: pool, tableName: 'user_sessions' }), // ★ ここでテーブル名を指定するだけでOK
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        secure: 'auto',
        httpOnly: true,
        sameSite: 'lax'
    }
}));
app.use(passport.initialize());
app.use(passport.session());
passport.use(new LocalStrategy(
    async (username, password, done) => {
        try {
            const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
            if (rows.length === 0) { return done(null, false, { message: 'ユーザー名またはパスワードが違います。' }); }
            const user = rows[0];
            const isMatch = await bcrypt.compare(password, user.password_hash);
            if (isMatch) { return done(null, user); }
            else { return done(null, false, { message: 'ユーザー名またはパスワードが違います。' }); }
        } catch (error) { return done(error); }
    }
));
passport.serializeUser((user, done) => { done(null, user.id); });
passport.deserializeUser(async (id, done) => {
    try {
        const { rows } = await pool.query('SELECT id, username FROM users WHERE id = $1', [id]);
        if (rows.length > 0) { done(null, rows[0]); }
        else { done(new Error('User not found')); }
    } catch (error) { done(error); }
});
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) { return next(); }
    res.status(401).json({ message: 'ログインが必要です。' });
}
// --- ▲ 認証機能ここまで ▲ ---


// --- ▼▼▼ DBテーブル自動作成関数 (user_sessions 関連を削除) ▼▼▼ ---
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
    const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password_hash VARCHAR(100) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`;
    // ★ createSessionTable 定数を削除

    const createFoldersTable = `
    CREATE TABLE IF NOT EXISTS folders (
      id SERIAL PRIMARY KEY,
      category_1 VARCHAR(100) NOT NULL,
      category_2 VARCHAR(100) NOT NULL,
      category_3 VARCHAR(100) NOT NULL,
      folder_name VARCHAR(100) NOT NULL,
      sort_order INTEGER DEFAULT 0,
      UNIQUE(category_1, category_2, category_3, folder_name)
    );
    `;

    const alterColumns = [
        `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_1') THEN ALTER TABLE images ADD COLUMN category_1 VARCHAR(100) DEFAULT 'default_cat1'; END IF; END $$;`,
        `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_2') THEN ALTER TABLE images ADD COLUMN category_2 VARCHAR(100) DEFAULT 'default_cat2'; END IF; END $$;`,
        `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_3') THEN ALTER TABLE images ADD COLUMN category_3 VARCHAR(100) DEFAULT 'default_cat3'; END IF; END $$;`,
        `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='folder_name') THEN ALTER TABLE images ADD COLUMN folder_name VARCHAR(100) DEFAULT 'default_folder'; END IF; END $$;`
    ];

    const createIndexes = [
        `CREATE INDEX IF NOT EXISTS idx_images_cat1 ON images (category_1);`,
        `CREATE INDEX IF NOT EXISTS idx_images_cat1_cat2 ON images (category_1, category_2);`,
        `CREATE INDEX IF NOT EXISTS idx_images_cat1_cat2_cat3 ON images (category_1, category_2, category_3);`,
        `CREATE INDEX IF NOT EXISTS idx_images_folder_name ON images (folder_name);`,
        `CREATE INDEX IF NOT EXISTS idx_images_title_length_and_title ON images (length(title), title);`,
        `CREATE INDEX IF NOT EXISTS idx_folders_cats ON folders (category_1, category_2, category_3);`
    ];

    try {
        await pool.query(createImagesTable);
        await pool.query(createUsersTable);
        // ★ await pool.query(createSessionTable); を削除
        await pool.query(createFoldersTable);

        for (const query of alterColumns) { await pool.query(query); }
        console.log('Database tables altered.');
        for (const query of createIndexes) { await pool.query(query); }
        console.log('Database indexes created.');
        console.log('Database tables ready.');
    } catch (err) { console.error('DB init error:', err); }
};
// --- ▲▲▲ DBテーブル自動作成関数 ▲▲▲ ---

// --- ストレージ (R2) 接続 (変更なし) ---
const r2Endpoint = `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
const r2PublicUrl = process.env.R2_PUBLIC_URL;
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME;
const s3Client = new S3Client({
    region: 'auto', endpoint: r2Endpoint,
    credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY },
});

// --- Multer (アップロード処理) 設定 (変更なし) ---
const upload = multer({
    storage: multerS3({
        s3: s3Client, bucket: R2_BUCKET_NAME, acl: 'public-read',
        key: function (req, file, cb) {
            const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
            cb(null, originalName);
        },
        contentType: multerS3.AUTO_CONTENT_TYPE
    }),
    fileFilter: (req, file, cb) => { if (file.mimetype.startsWith('image/')) { cb(null, true); } else { cb(new Error('画像のみ'), false); } }
});

// -----------------------------------------------------------------
// ★★★★★ ルート（URL）設定 ★★★★★
// -----------------------------------------------------------------

// --- 認証ルート ---
app.get('/login', (req, res) => { res.sendFile(path.join(__dirname, 'login.html')); });
app.get('/register', (req, res) => { res.sendFile(path.join(__dirname, 'register.html')); });
app.post('/api/auth/register', async (req, res) => { /* (変更なし) */ });
app.post('/api/auth/login', passport.authenticate('local'), (req, res) => { /* (変更なし) */ });
app.post('/api/auth/logout', (req, res, next) => { /* (変更なし) */ });
app.get('/api/auth/check', (req, res) => { /* (変更なし) */ });

// ★ メインページ ( / ) (変更なし)
app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

// ==================================================================
// ▼▼▼ アップロードAPI (/upload) ▼▼▼
// ==================================================================
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => { /* (変更なし) */ });

// ==================================================================
// ▼▼▼ CSV API (/download-csv) ▼▼▼
// ==================================================================
app.get('/download-csv', isAuthenticated, async (req, res) => { /* (変更なし) */ });


// ==================================================================
// ▼▼▼ ギャラリー・編集・削除 API (★ NULL対策の修正) ▼▼▼
// ==================================================================

// --- ★ NULL値をデフォルト値（'default_catX'）に置き換えるヘルパー ---
const defaultCat1 = 'default_cat1';
const defaultCat2 = 'default_cat2';
const defaultCat3 = 'default_cat3';
const defaultFolder = 'default_folder';

// --- ▼▼▼ /api/cat1 を修正 (NULL対策 + 詳細ログ) ▼▼▼ ---
app.get('/api/cat1', isAuthenticated, async (req, res) => {
    console.log("[API /api/cat1] Request received."); // Log start
    try {
        const query = `SELECT DISTINCT COALESCE(category_1, '${defaultCat1}') AS category_1 FROM images ORDER BY category_1`;
        console.log("[API /api/cat1] Executing query:", query); // Log query
        const start = Date.now(); // ★ 時間計測開始
        const { rows } = await pool.query(query);
        const duration = Date.now() - start; // ★ 時間計測終了
        console.log(`[API /api/cat1] Query successful, found ${rows.length} distinct categories in ${duration}ms.`); // Log success + 時間
        res.json(rows.map(r => r.category_1));
        console.log("[API /api/cat1] Response sent."); // Log end
    } catch (e) {
        console.error("!!!!! API /api/cat1 FAILED !!!!!", e); // Log error
        res.status(500).json({ message: 'Error fetching cat1' });
    }
});
// --- ▲▲▲ /api/cat1 ▲▲▲ ---

// --- ▼▼▼ /api/cat2 を修正 (NULL対策) ▼▼▼ ---
app.get('/api/cat2/:cat1', isAuthenticated, async (req, res) => {
    try {
        const { cat1 } = req.params;
        const query = (cat1 === defaultCat1)
            ? `SELECT DISTINCT COALESCE(category_2, '${defaultCat2}') AS category_2 FROM images WHERE (category_1 = $1 OR category_1 IS NULL) ORDER BY category_2`
            : `SELECT DISTINCT COALESCE(category_2, '${defaultCat2}') AS category_2 FROM images WHERE category_1 = $1 ORDER BY category_2`;

        const { rows } = await pool.query(query, [cat1]);
        res.json(rows.map(r => r.category_2));
    } catch (e) { console.error("!!!!! API /api/cat2 FAILED !!!!!", e); res.status(500).json({ message: 'Error fetching cat2' }); }
});
// --- ▲▲▲ /api/cat2 ▲▲▲ ---

// --- ▼▼▼ /api/cat3 を修正 (NULL対策) ▼▼▼ ---
app.get('/api/cat3/:cat1/:cat2', isAuthenticated, async (req, res) => {
    try {
        const { cat1, cat2 } = req.params;

        const whereCat1 = (cat1 === defaultCat1) ? `(category_1 = $1 OR category_1 IS NULL)` : `category_1 = $1`;
        const whereCat2 = (cat2 === defaultCat2) ? `(category_2 = $2 OR category_2 IS NULL)` : `category_2 = $2`;

        const query = `
            SELECT DISTINCT COALESCE(category_3, '${defaultCat3}') AS category_3
            FROM images
            WHERE ${whereCat1} AND ${whereCat2}
            ORDER BY category_3
        `;

        const { rows } = await pool.query(query, [cat1, cat2]);
        res.json(rows.map(r => r.category_3));
    } catch (e) { console.error("!!!!! API /api/cat3 FAILED !!!!!", e); res.status(500).json({ message: 'Error fetching cat3' }); }
});
// --- ▲▲▲ /api/cat3 ▲▲▲ ---


// --- ▼▼▼ /api/folders を修正 (NULL対策・バグ修正) ▼▼▼ ---
app.get('/api/folders/:cat1/:cat2/:cat3', isAuthenticated, async (req, res) => {
    const { cat1, cat2, cat3 } = req.params;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // 1. Build WHERE clauses and params for sync query
        const conditions = [];
        const paramsSync = [];
        let paramIndex = 1;

        if (cat1 === defaultCat1) {
            conditions.push(`(category_1 = $${paramIndex++} OR category_1 IS NULL)`);
            paramsSync.push(cat1);
        } else {
            conditions.push(`category_1 = $${paramIndex++}`);
            paramsSync.push(cat1);
        }

        if (cat2 === defaultCat2) {
            conditions.push(`(category_2 = $${paramIndex++} OR category_2 IS NULL)`);
            paramsSync.push(cat2);
        } else {
            conditions.push(`category_2 = $${paramIndex++}`);
            paramsSync.push(cat2);
        }

        if (cat3 === defaultCat3) {
            conditions.push(`(category_3 = $${paramIndex++} OR category_3 IS NULL)`);
            paramsSync.push(cat3);
        } else {
            conditions.push(`category_3 = $${paramIndex++}`);
            paramsSync.push(cat3);
        }

        // 2. images -> folders sync query (Using parameterized WHERE)
        const syncQuery = `
            INSERT INTO folders (category_1, category_2, category_3, folder_name)
            SELECT DISTINCT
                COALESCE(category_1, '${defaultCat1}'),
                COALESCE(category_2, '${defaultCat2}'),
                COALESCE(category_3, '${defaultCat3}'),
                COALESCE(folder_name, '${defaultFolder}')
            FROM images
            WHERE ${conditions.join(' AND ')}
            ON CONFLICT (category_1, category_2, category_3, folder_name) DO NOTHING
        `;
        await client.query(syncQuery, paramsSync); // Pass parameters here

        // 3. Get folders from 'folders' table (Uses parameters directly)
        const selectQuery = `
            SELECT folder_name
            FROM folders
            WHERE category_1 = $1 AND category_2 = $2 AND category_3 = $3
            ORDER BY sort_order ASC, folder_name ASC
        `;
        const { rows } = await client.query(selectQuery, [cat1, cat2, cat3]);

        await client.query('COMMIT');
        res.json(rows.map(r => r.folder_name));
    } catch (e) {
        await client.query('ROLLBACK');
        console.error("!!!!! API /api/folders FAILED !!!!!", e);
        res.status(500).json({ message: 'Error fetching folders' });
    } finally {
        client.release();
    }
});
// --- ▲▲▲ /api/folders ▲▲▲ ---

// --- ▼▼▼ フォルダ並び替えAPIを新規追加 ▼▼▼ ---
app.post('/api/folders/reorder', isAuthenticated, async (req, res) => {
    const { category1, category2, category3, orderedFolderNames } = req.body;

    if (!category1 || !category2 || !category3 || !Array.isArray(orderedFolderNames)) {
        return res.status(400).json({ message: '不正なリクエストです' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        for (let i = 0; i < orderedFolderNames.length; i++) {
            const folderName = orderedFolderNames[i];
            const sortOrder = i;

            await client.query(
                `UPDATE folders
                 SET sort_order = $1
                 WHERE category_1 = $2 AND category_2 = $3 AND category_3 = $4 AND folder_name = $5`,
                [sortOrder, category1, category2, category3, folderName]
            );
        }

        await client.query('COMMIT');
        res.json({ message: 'フォルダの並び順を保存しました。' });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error("!!!!! API /api/folders/reorder FAILED !!!!!", e);
        res.status(500).json({ message: '並び順の保存に失敗しました。' });
    } finally {
        client.release();
    }
});
// --- ▲▲▲ フォルダ並び替えAPIを新規追加 ▲▲▲ ---

app.get('/api/images/:folderName', isAuthenticated, async (req, res) => { /* (変更なし) */ });
app.get('/api/search', isAuthenticated, async (req, res) => { /* (変更なし) */ });

// --- カテゴリ・フォルダ編集API ---
app.put('/api/cat1/:oldName', isAuthenticated, async (req, res) => { /* (変更なし) */ });
app.put('/api/cat2/:cat1/:oldName', isAuthenticated, async (req, res) => { /* (変更なし) */ });
app.put('/api/cat3/:cat1/:cat2/:oldName', isAuthenticated, async (req, res) => { /* (変更なし) */ });

// --- ▼▼▼ フォルダ名変更 (PUT /api/folder) を修正 (NULL対策) ▼▼▼ ---
app.put('/api/folder/:cat1/:cat2/:cat3/:oldName', isAuthenticated, async (req, res) => { /* (変更なし) */ });
// --- ▲▲▲ フォルダ名変更 (PUT /api/folder) ▲▲▲ ---

// --- ▼▼▼ performDelete 関数 と 削除API群を修正 (NULL対策) ▼▼▼ ---
async function performDelete(res, itemDescription, levelData = {}) { /* (変更なし) */ }
app.delete('/api/cat1/:name', isAuthenticated, async (req, res) => { /* (変更なし) */ });
app.delete('/api/cat2/:cat1/:name', isAuthenticated, async (req, res) => { /* (変更なし) */ });
app.delete('/api/cat3/:cat1/:cat2/:name', isAuthenticated, async (req, res) => { /* (変更なし) */ });
app.delete('/api/folder/:cat1/:cat2/:cat3/:name', isAuthenticated, async (req, res) => { /* (変更なし) */ });
// --- ▲▲▲ performDelete 関数 と 削除API群を修正 ▲▲▲ ---


// --- 画像移動API ---
app.put('/api/image/:imageTitle', isAuthenticated, async (req, res) => { /* (変更なし) */ });

// --- 解析API (Tesseract.js 版) ---
app.post('/api/analyze/:folderName', isAuthenticated, async (req, res) => { /* (変更なし) */ });


// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable();
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});