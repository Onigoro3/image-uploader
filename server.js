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

    // ▼▼▼ フォルダ並び替え機能 (テーブル・インデックス追加) ▼▼▼
    const createFolderMetaTable = `
    CREATE TABLE IF NOT EXISTS folder_metadata (
      id SERIAL PRIMARY KEY,
      category_1 VARCHAR(100) NOT NULL,
      category_2 VARCHAR(100) NOT NULL,
      category_3 VARCHAR(100) NOT NULL,
      folder_name VARCHAR(100) NOT NULL,
      sort_order INT DEFAULT 0,
      UNIQUE(category_1, category_2, category_3, folder_name)
    );`;

    const createFolderMetaIndex = `
    CREATE INDEX IF NOT EXISTS idx_folder_meta_cats_order ON 
    folder_metadata (category_1, category_2, category_3, sort_order ASC, folder_name ASC);
    `;

    // 既存データを folder_metadata に移行するクエリ
    const migrateFolders = `
    INSERT INTO folder_metadata (category_1, category_2, category_3, folder_name, sort_order)
    SELECT 
      category_1, 
      category_2, 
      category_3, 
      folder_name,
      ROW_NUMBER() OVER(
        PARTITION BY category_1, category_2, category_3 
        ORDER BY MIN(created_at) ASC, folder_name ASC
      ) - 1 as sort_order
    FROM images
    GROUP BY category_1, category_2, category_3, folder_name
    ON CONFLICT (category_1, category_2, category_3, folder_name) DO NOTHING;
    `;
    // ▲▲▲ フォルダ並び替え機能 (テーブル・インデックス追加) ▲▲▲
    
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
        
        // ▼▼▼ フォルダ並び替え機能 (実行) ▼▼▼
        await pool.query(createFolderMetaTable);
        await pool.query(createFolderMetaIndex);
        // ▲▲▲ フォルダ並び替え機能 (実行) ▲▲▲

        for (const query of alterColumns) { await pool.query(query); }
        console.log('Database tables altered.');
        for (const query of createIndexes) { await pool.query(query); }
        console.log('Database indexes created.');

        // ▼▼▼ フォルダ並び替え機能 (データ移行) ▼▼▼
        try {
            const migrationResult = await pool.query(migrateFolders);
            if (migrationResult.rowCount > 0) {
                console.log(`Migrated ${migrationResult.rowCount} existing folders to folder_metadata.`);
            }
        } catch (migrateError) {
            console.error('Folder migration error (might be ok if already run):', migrateError);
        }
        // ▲▲▲ フォルダ並び替え機能 (データ移行) ▲▲▲

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

        // ▼▼▼ フォルダ並び替え機能 (メタデータ登録) ▼▼▼
        const metaQuery = `
        INSERT INTO folder_metadata (category_1, category_2, category_3, folder_name, sort_order)
        VALUES ($1, $2, $3, $4, 
          (
            SELECT COALESCE(MAX(sort_order), -1) + 1 
            FROM folder_metadata 
            WHERE category_1 = $1 AND category_2 = $2 AND category_3 = $3
          )
        )
        ON CONFLICT (category_1, category_2, category_3, folder_name) DO NOTHING;
        `;
        // フォルダ名は1つなので、ループの外で1回だけ実行
        await pool.query(metaQuery, [cat1Trimmed, cat2Trimmed, cat3Trimmed, folderNameTrimmed]);
        // ▲▲▲ フォルダ並び替え機能 (メタデータ登録) ▲▲▲

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

// ▼▼▼ フォルダ並び替え機能 (API修正) ▼▼▼
// (folder_metadata テーブルから sort_order 順に取得する)
app.get('/api/folders/:cat1/:cat2/:cat3', isAuthenticated, async (req, res) => { 
    try { 
        console.log(`[API] /api/folders received`); 
        const { rows } = await pool.query(
            `SELECT folder_name FROM folder_metadata 
             WHERE category_1 = $1 AND category_2 = $2 AND category_3 = $3 
             ORDER BY sort_order ASC, folder_name ASC`, 
            [req.params.cat1, req.params.cat2, req.params.cat3]
        ); 
        console.log(`[API] /api/folders found ${rows.length}`); 
        res.json(rows.map(r => r.folder_name)); 
    } catch (e) { 
        console.error("!!!!! API /api/folders FAILED !!!!!", e); 
        res.status(500).json({ message: 'Error fetching folders' }); 
    } 
});
// ▲▲▲ フォルダ並び替え機能 (API修正) ▲▲▲

app.get('/api/images/:folderName', isAuthenticated, async (req, res) => { try { console.log(`[API] /api/images/${req.params.folderName} received`); const sortBy = req.query.sort === 'title' ? 'title' : 'created_at'; const sortOrder = req.query.order === 'ASC' ? 'ASC' : 'DESC'; const qT = `SELECT title, url FROM images WHERE folder_name = $1 ORDER BY ${sortBy} ${sortOrder}, id ${sortOrder}`; const { rows } = await pool.query(qT, [req.params.folderName]); console.log(`[API] /api/images found ${rows.length}`); res.json(rows); } catch (e) { console.error("!!!!! API /api/images FAILED !!!!!", e); res.status(500).json({ message: 'Error fetching images' }); } });
app.get('/api/search', isAuthenticated, async (req, res) => { const { folder, q } = req.query; console.log(`[API] /api/search received (folder: ${folder}, q: ${q})`); const sortBy = req.query.sort === 'title' ? 'title' : 'created_at'; const sortOrder = req.query.order === 'ASC' ? 'ASC' : 'DESC'; if (!folder) { return res.status(400).json({ message: 'フォルダ指定必須' }); } try { let qT; let qP; const oBC = `ORDER BY ${sortBy} ${sortOrder}, id ${sortOrder}`; if (q && q.trim() !== '') { const s = `%${q}%`; qT = `SELECT title, url FROM images WHERE folder_name = $1 AND title ILIKE $2 ${oBC}`; qP = [folder, s]; } else { qT = `SELECT title, url FROM images WHERE folder_name = $1 ${oBC}`; qP = [folder]; } const { rows } = await pool.query(qT, qP); console.log(`[API] /api/search found ${rows.length}`); res.json(rows); } catch (e) { console.error("!!!!! API /api/search FAILED !!!!!", e); res.status(500).json({ message: '検索失敗' }); } });

// --- カテゴリ・フォルダ編集API ---
app.put('/api/cat1/:oldName', isAuthenticated, async (req, res) => { const { oldName } = req.params; const { newName } = req.body; if (!newName || newName.trim() === '' || newName.trim() === oldName) return res.status(400).json({message: 'Invalid name'}); try { await pool.query('UPDATE images SET category_1 = $1 WHERE category_1 = $2', [newName.trim(), oldName]); res.json({ message: `大カテゴリ名変更完了` }); } catch (e) { console.error("Rename Cat1 Error:", e); res.status(500).json({ message: '名前変更失敗' }); } });
app.put('/api/cat2/:cat1/:oldName', isAuthenticated, async (req, res) => { const { cat1, oldName } = req.params; const { newName } = req.body; if (!newName || newName.trim() === '' || newName.trim() === oldName) return res.status(400).json({message: 'Invalid name'}); try { await pool.query('UPDATE images SET category_2 = $1 WHERE category_1 = $2 AND category_2 = $3', [newName.trim(), cat1, oldName]); res.json({ message: `中カテゴリ名変更完了` }); } catch (e) { console.error("Rename Cat2 Error:", e); res.status(500).json({ message: '名前変更失敗' }); } });
app.put('/api/cat3/:cat1/:cat2/:oldName', isAuthenticated, async (req, res) => { const { cat1, cat2, oldName } = req.params; const { newName } = req.body; if (!newName || newName.trim() === '' || newName.trim() === oldName) return res.status(400).json({message: 'Invalid name'}); try { await pool.query('UPDATE images SET category_3 = $1 WHERE category_1 = $2 AND category_2 = $3 AND category_3 = $4', [newName.trim(), cat1, cat2, oldName]); res.json({ message: `小カテゴリ名変更完了` }); } catch (e) { console.error("Rename Cat3 Error:", e); res.status(500).json({ message: '名前変更失敗' }); } });

// ▼▼▼ フォルダ並び替え機能 (フォルダ名変更API 修正) ▼▼▼
// (folder_metadata テーブルも同時に更新する)
app.put('/api/folder/:oldName', isAuthenticated, async (req, res) => { 
    const { oldName } = req.params; 
    const { newName } = req.body; 
    
    // ★ index.html から cat1, cat2, cat3 をクエリパラメータで受け取る
    const { cat1, cat2, cat3 } = req.query; 
    const newNameTrimmed = (newName || '').trim();
    
    if (!newName || newNameTrimmed === '' || newNameTrimmed === oldName) return res.status(400).json({message: '無効な名前です'});
    if (!cat1 || !cat2 || !cat3) return res.status(400).json({ message: 'カテゴリ指定(cat1, cat2, cat3)がクエリに必要です。' });

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // 1. images テーブルを更新
        const imagesUpdate = await client.query(
            'UPDATE images SET folder_name = $1 WHERE folder_name = $2 AND category_1 = $3 AND category_2 = $4 AND category_3 = $5', 
            [newNameTrimmed, oldName, cat1, cat2, cat3]
        );

        // 2. folder_metadata テーブルを更新
        const metaUpdate = await client.query(
            'UPDATE folder_metadata SET folder_name = $1 WHERE folder_name = $2 AND category_1 = $3 AND category_2 = $4 AND category_3 = $5',
            [newNameTrimmed, oldName, cat1, cat2, cat3]
        );

        await client.query('COMMIT');
        
        if (imagesUpdate.rowCount === 0 && metaUpdate.rowCount === 0) {
            res.status(404).json({ message: '対象フォルダが見つかりません' });
        } else {
            res.json({ message: `フォルダ名変更完了 (Img: ${imagesUpdate.rowCount}件)` });
        }
    } catch (e) { 
        await client.query('ROLLBACK');
        console.error("Rename Folder Error:", e); 
        if (e.code === '23505') { // unique_violation
            res.status(409).json({ message: 'その名前はすでに使用されています' });
        } else {
            res.status(500).json({ message: '名前変更失敗' }); 
        }
    } finally {
        client.release();
    }
});
// ▲▲▲ フォルダ並び替え機能 (フォルダ名変更API 修正) ▲▲▲

// --- カテゴリ・フォルダ削除API ---
async function performDelete(res, conditions, params, itemDescription) {
    // ★注意: この関数は /api/folder 以外 (cat1, cat2, cat3) でのみ使用される
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. R2から画像ファイル削除
        const { rows } = await client.query(`SELECT title FROM images WHERE ${conditions}`, params);
        if (rows.length > 0) {
            const objectsToDelete = rows.map(row => ({ Key: row.title }));
            for (let i = 0; i < objectsToDelete.length; i += 1000) { const chunk = objectsToDelete.slice(i, i + 1000); const deleteCommand = new DeleteObjectsCommand({ Bucket: R2_BUCKET_NAME, Delete: { Objects: chunk } }); await s3Client.send(deleteCommand); console.log(`Deleted ${chunk.length} R2 objects`); }
        }
        
        // 2. images テーブルから削除
        const deleteResult = await client.query(`DELETE FROM images WHERE ${conditions}`, params); 
        console.log(`Deleted ${deleteResult.rowCount} DB records for ${itemDescription}`);

        // 3. folder_metadata テーブルからも削除
        // (cat1, cat2, cat3 の削除は、それらに紐づく folder_metadata も削除する必要がある)
        const metaDeleteResult = await client.query(`DELETE FROM folder_metadata WHERE ${conditions}`, params);
        console.log(`Deleted ${metaDeleteResult.rowCount} metadata records for ${itemDescription}`);

        await client.query('COMMIT');
        res.json({ message: `${itemDescription} 削除完了` });
    } catch (error) { 
        await client.query('ROLLBACK');
        console.error(`Delete Error:`, error); 
        res.status(500).json({ message: '削除失敗' }); 
    } finally {
        client.release();
    }
}
app.delete('/api/cat1/:name', isAuthenticated, async (req, res) => { await performDelete(res, 'category_1 = $1', [req.params.name], `大カテゴリ「${req.params.name}」`); });
app.delete('/api/cat2/:cat1/:name', isAuthenticated, async (req, res) => { await performDelete(res, 'category_1 = $1 AND category_2 = $2', [req.params.cat1, req.params.name], `中カテゴリ「${req.params.name}」`); });
app.delete('/api/cat3/:cat1/:cat2/:name', isAuthenticated, async (req, res) => { await performDelete(res, 'category_1 = $1 AND category_2 = $2 AND category_3 = $3', [req.params.cat1, req.params.cat2, req.params.name], `小カテゴリ「${req.params.name}」`); });

// ▼▼▼ フォルダ並び替え機能 (フォルダ削除API 修正) ▼▼▼
// (folder_metadata テーブルも同時に削除する)
app.delete('/api/folder/:name', isAuthenticated, async (req, res) => { 
    const { name } = req.params;
    
    // ★ index.html から cat1, cat2, cat3 をクエリパラメータで受け取る
    const { cat1, cat2, cat3 } = req.query; 
    if (!cat1 || !cat2 || !cat3) {
        return res.status(400).json({ message: 'カテゴリ指定(cat1, cat2, cat3)がクエリに必要です。' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const conditions = 'folder_name = $1 AND category_1 = $2 AND category_2 = $3 AND category_3 = $4';
        const params = [name, cat1, cat2, cat3];
        const itemDescription = `フォルダ「${name}」`;

        // 1. R2から画像ファイル削除
        const { rows } = await client.query(`SELECT title FROM images WHERE ${conditions}`, params);
        if (rows.length > 0) {
            const objectsToDelete = rows.map(row => ({ Key: row.title }));
            for (let i = 0; i < objectsToDelete.length; i += 1000) { 
                const chunk = objectsToDelete.slice(i, i + 1000); 
                const deleteCommand = new DeleteObjectsCommand({ Bucket: R2_BUCKET_NAME, Delete: { Objects: chunk } }); 
                await s3Client.send(deleteCommand); 
                console.log(`Deleted ${chunk.length} R2 objects`); 
            }
        }
        
        // 2. images テーブルから削除
        const deleteImagesResult = await client.query(`DELETE FROM images WHERE ${conditions}`, params); 
        console.log(`Deleted ${deleteImagesResult.rowCount} DB records for ${itemDescription}`);

        // 3. folder_metadata テーブルから削除
        const deleteMetaResult = await client.query(`DELETE FROM folder_metadata WHERE ${conditions}`, params);
        console.log(`Deleted ${deleteMetaResult.rowCount} metadata records for ${itemDescription}`);
        
        await client.query('COMMIT');
        res.json({ message: `${itemDescription} 削除完了` });

    } catch (error) { 
        await client.query('ROLLBACK');
        console.error(`Delete Error:`, error); 
        res.status(500).json({ message: '削除失敗' }); 
    } finally {
        client.release();
    }
});
// ▲▲▲ フォルダ並び替え機能 (フォルダ削除API 修正) ▲▲▲

// --- 画像移動API ---
app.put('/api/image/:imageTitle', isAuthenticated, async (req, res) => {
    const { imageTitle } = req.params; const { category1, category2, category3, folderName } = req.body;
    if (!category1 || !category2 || !category3 || !folderName) { return res.status(400).json({ message: '移動先指定必須' }); }
    // ★ TODO: 画像移動時も、移動先の folder_metadata が存在するかチェックし、なければ作成するロジックが推奨されます
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

// ▼▼▼ フォルダ並び替え機能 (並び替えAPI) ▼▼▼
// (index.html の saveFolderOrder 関数から呼び出される)
app.post('/api/folders/reorder', isAuthenticated, async (req, res) => {
    // index.html から { cat1: "...", cat2: "...", cat3: "...", orderedFolders: [ {folder_name: "A", order: 0}, {folder_name: "B", order: 1} ] }
    // という形式のデータを受け取る
    const { cat1, cat2, cat3, orderedFolders } = req.body;

    if (!cat1 || !cat2 || !cat3 || !Array.isArray(orderedFolders)) {
        return res.status(400).json({ message: 'カテゴリ指定とフォルダリスト配列が必要です。' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // バルクアップデート (一括更新) のために CASE 文を構築
        if (orderedFolders.length > 0) {
            const sortOrderUpdates = [];
            const folderNameParams = [];
            
            // $1, $2, $3 は cat1, cat2, cat3 で使用
            let paramIndex = 4; 

            // orderedFolders 配列をループして、SQLのCASE文とパラメータ配列を作成
            orderedFolders.forEach(item => {
                // "WHEN folder_name = $4 THEN $5" のようなSQL文の一部
                sortOrderUpdates.push(`WHEN folder_name = $${paramIndex++} THEN $${paramIndex++}`);
                // パラメータ配列に ["Fusion", 0] のように追加
                folderNameParams.push(item.folder_name, item.order);
            });

            // "IN ($4, $6, $8, ...)" のようなSQL文の一部
            const folderNamesList = orderedFolders.map((_, i) => `$${4 + i*2}`);
            
            const updateQuery = `
            UPDATE folder_metadata SET
              sort_order = CASE ${sortOrderUpdates.join(' ')} END
            WHERE 
              category_1 = $1 
              AND category_2 = $2 
              AND category_3 = $3
              AND folder_name IN (${folderNamesList.join(', ')});
            `;

            // 最終的なパラメータ配列 [cat1, cat2, cat3, "Fusion", 0, "Link", 1, ...]
            const queryParams = [cat1, cat2, cat3, ...folderNameParams];
            
            // SQL実行
            await client.query(updateQuery, queryParams);
        }

        await client.query('COMMIT');
        res.json({ message: 'フォルダの並び順を更新しました。' });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Reorder Folders Error:', error);
        res.status(500).json({ message: '並び順の更新に失敗しました。' });
    } finally {
        client.release();
    }
});
// ▲▲▲ フォルダ並び替え機能 (並び替えAPI) ▲▲▲

// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable();
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});