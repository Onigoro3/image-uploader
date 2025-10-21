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
    secret: process.env.SESSION_SECRET, // ★ .env から読み込む
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        secure: 'auto', // Render
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
            // UTF-8ファイル名対応
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

// --- ▼▼▼【*復元*】新規登録 API ---
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) { return res.status(400).json({ message: 'ユーザー名とパスワードは必須です。' }); }
    try {
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        const { rows } = await pool.query(
            'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id',
            [username, passwordHash]
        );
        res.status(201).json({ message: '登録が成功しました。', userId: rows[0].id });
    } catch (error) {
        console.error("Register Error:", error);
        if (error.code === '23505') { // Unique violation
            res.status(409).json({ message: 'そのユーザー名はすでに使用されています。' });
        } else {
            res.status(500).json({ message: '登録中にエラーが発生しました。' });
        }
    }
});
// --- ▲▲▲【*復元*】新規登録 API ---

// --- ▼▼▼【*復元*】ログイン API ---
app.post('/api/auth/login', passport.authenticate('local'), (req, res) => {
    // passport.authenticate が成功すると、req.user が設定される
    res.json({ message: 'ログイン成功', username: req.user.username });
});
// --- ▲▲▲【*復元*】ログイン API ---

// --- ▼▼▼【*復元*】ログアウト API ---
app.post('/api/auth/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        req.session.destroy((err) => {
            if (err) {
                return res.status(500).json({ message: 'ログアウト中にセッションの破棄に失敗しました。' });
            }
            res.clearCookie('connect.sid'); // セッションCookieをクリア
            res.json({ message: 'ログアウトしました。' });
        });
    });
});
// --- ▲▲▲【*復元*】ログアウト API ---

// --- ▼▼▼【*復元*】ログイン状態チェック API ---
app.get('/api/auth/check', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ loggedIn: true, username: req.user.username });
    } else {
        res.json({ loggedIn: false });
    }
});
// --- ▲▲▲【*復元*】ログイン状態チェック API ---


// ★ メインページ ( / ) (変更なし)
app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

// ==================================================================
// ▼▼▼【*復元*】アップロードAPI (/upload) ▼▼▼
// ==================================================================
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => {
    const { category1, category2, category3, folderName } = req.body;
    const files = req.files;

    if (!files || files.length === 0) {
        return res.status(400).json({ message: 'ファイルが選択されていません。' });
    }
    if (!category1 || !category2 || !category3 || !folderName) {
        return res.status(400).json({ message: 'カテゴリとフォルダ名は必須です。' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        for (const file of files) {
            // S3/R2 の URL (キーから構築)
            // UTF-8ファイル名対応
            const originalName = Buffer.from(file.key, 'latin1').toString('utf8');
            const imageUrl = `${r2PublicUrl}/${encodeURIComponent(originalName)}`;
            
            // DBに保存 (title には R2 のキー (ファイル名) を保存)
            await client.query(
                `INSERT INTO images (title, url, category_1, category_2, category_3, folder_name)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [originalName, imageUrl, category1, category2, category3, folderName]
            );
        }
        
        // フォルダテーブルにも同期
        await client.query(
            `INSERT INTO folders (category_1, category_2, category_3, folder_name)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (category_1, category_2, category_3, folder_name) DO NOTHING`,
            [category1, category2, category3, folderName]
        );

        await client.query('COMMIT');
        res.json({ message: `${files.length} ファイルのアップロードが完了しました。` });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Upload Error:', error);
        res.status(500).json({ message: 'アップロード中にエラーが発生しました。' });
    } finally {
        client.release();
    }
});
// ==================================================================
// ▲▲▲【*復元*】アップロードAPI (/upload) ▲▲▲
// ==================================================================


// ==================================================================
// ▼▼▼【*復元*】CSV API (/download-csv) ▼▼▼
// ==================================================================
app.get('/download-csv', isAuthenticated, async (req, res) => {
    const { folder } = req.query;
    if (!folder) {
        return res.status(400).send('フォルダが指定されていません。');
    }

    try {
        // NULL値もデフォルト値で取得
        const { rows } = await pool.query(
            `SELECT 
                id, 
                title, 
                url, 
                COALESCE(category_1, 'default_cat1') AS category_1,
                COALESCE(category_2, 'default_cat2') AS category_2,
                COALESCE(category_3, 'default_cat3') AS category_3,
                COALESCE(folder_name, 'default_folder') AS folder_name,
                created_at
             FROM images 
             WHERE folder_name = $1 OR ($1 = 'default_folder' AND folder_name IS NULL)
             ORDER BY title ASC`,
            [folder]
        );

        if (rows.length === 0) {
            return res.status(404).send('そのフォルダに画像はありません。');
        }

        // CSVヘッダー
        let csv = 'ID,ファイル名,画像URL,大カテゴリ,中カテゴリ,小カテゴリ,フォルダ名,アップロード日時\n';
        
        // CSVボディ
        rows.forEach(row => {
            csv += [
                row.id,
                `"${row.title.replace(/"/g, '""')}"`, // ファイル名 (")
                `"${row.url.replace(/"/g, '""')}"`, // URL (")
                `"${row.category_1.replace(/"/g, '""')}"`,
                `"${row.category_2.replace(/"/g, '""')}"`,
                `"${row.category_3.replace(/"/g, '""')}"`,
                `"${row.folder_name.replace(/"/g, '""')}"`,
                row.created_at.toISOString()
            ].join(',') + '\n';
        });

        const safeFolderName = folder.replace(/[^a-z0-9]/gi, '_').toLowerCase();
        const fileName = `export_${safeFolderName}_${new Date().toISOString().split('T')[0]}.csv`;

        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        // UTF-8のBOM (Excelで文字化けさせないため)
        res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`);
        res.send(Buffer.concat([Buffer.from('\uFEFF', 'utf8'), Buffer.from(csv, 'utf8')]));

    } catch (error) {
        console.error('CSV Download Error:', error);
        res.status(500).send('CSVの生成中にエラーが発生しました。');
    }
});
// ==================================================================
// ▲▲▲【*復元*】CSV API (/download-csv) ▲▲▲
// ==================================================================


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
        // cat1 が 'default_cat1' の場合は、NULL のものも検索対象に含める
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

        // cat1, cat2 が 'default_... ' の場合は、NULL のものも検索対象に含める
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
        // images テーブルから folders テーブルへ同期する際の条件
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
        // imagesテーブルに存在するがfoldersテーブルにないフォルダを同期する
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
        // foldersテーブルから並び順(sort_order)を考慮して取得
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

        // 渡された配列の順序 (i) を sort_order として UPDATE
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

// --- ▼▼▼【*復元*】画像一覧取得 API ---
app.get('/api/images/:folderName', isAuthenticated, async (req, res) => {
    const { folderName } = req.params;
    const { sort = 'created_at', order = 'DESC' } = req.query; // ソート順
    
    // ソートの列名をホワイトリストで検証
    const validSortColumns = ['created_at', 'title'];
    const validSortOrders = ['ASC', 'DESC'];
    
    const sortBy = validSortColumns.includes(sort) ? sort : 'created_at';
    const sortOrder = validSortOrders.includes(order.toUpperCase()) ? order.toUpperCase() : 'DESC';

    try {
        const query = (folderName === defaultFolder)
            ? `SELECT title, url FROM images WHERE (folder_name = $1 OR folder_name IS NULL) ORDER BY ${sortBy} ${sortOrder}`
            : `SELECT title, url FROM images WHERE folder_name = $1 ORDER BY ${sortBy} ${sortOrder}`;
            
        const { rows } = await pool.query(query, [folderName]);
        res.json(rows);
    } catch (e) {
        console.error("!!!!! API /api/images FAILED !!!!!", e);
        res.status(500).json({ message: 'Error fetching images' });
    }
});
// --- ▲▲▲【*復元*】画像一覧取得 API ---

// --- ▼▼▼【*復元*】画像検索 API ---
app.get('/api/search', isAuthenticated, async (req, res) => {
    const { q, folder, sort = 'created_at', order = 'DESC' } = req.query;
    if (!q || !folder) { return res.status(400).json({ message: '検索語とフォルダが必要です' }); }

    const validSortColumns = ['created_at', 'title'];
    const validSortOrders = ['ASC', 'DESC'];
    const sortBy = validSortColumns.includes(sort) ? sort : 'created_at';
    const sortOrder = validSortOrders.includes(order.toUpperCase()) ? order.toUpperCase() : 'DESC';

    try {
        // folder_name の条件
        const folderCondition = (folder === defaultFolder)
            ? `(folder_name = $1 OR folder_name IS NULL)`
            : `folder_name = $1`;

        // 検索クエリ
        const query = `
            SELECT title, url 
            FROM images 
            WHERE ${folderCondition} AND title ILIKE $2 
            ORDER BY ${sortBy} ${sortOrder}
        `;
        
        const { rows } = await pool.query(query, [folder, `%${q}%`]);
        res.json(rows);
    } catch (e) {
        console.error("!!!!! API /api/search FAILED !!!!!", e);
        res.status(500).json({ message: 'Error searching images' });
    }
});
// --- ▲▲▲【*復元*】画像検索 API ---

// --- カテゴリ・フォルダ編集API ---

// --- ▼▼▼【*復元*】大カテゴリ名変更 (PUT /api/cat1) ---
app.put('/api/cat1/:oldName', isAuthenticated, async (req, res) => {
    const { oldName } = req.params;
    const { newName } = req.body;
    if (!newName) return res.status(400).json({ message: '新しい名前が必要です' });

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const imagesQuery = (oldName === defaultCat1)
            ? `UPDATE images SET category_1 = $1 WHERE category_1 IS NULL OR category_1 = $2`
            : `UPDATE images SET category_1 = $1 WHERE category_1 = $2`;
        await client.query(imagesQuery, [newName, oldName]);
        
        const foldersQuery = (oldName === defaultCat1)
            ? `UPDATE folders SET category_1 = $1 WHERE category_1 IS NULL OR category_1 = $2`
            : `UPDATE folders SET category_1 = $1 WHERE category_1 = $2`;
        await client.query(foldersQuery, [newName, oldName]);
        
        await client.query('COMMIT');
        res.json({ message: `大カテゴリ「${oldName}」を「${newName}」に変更しました。` });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error("!!!!! API PUT /api/cat1 FAILED !!!!!", e);
        res.status(500).json({ message: '大カテゴリ名の変更に失敗しました。' });
    } finally {
        client.release();
    }
});
// --- ▲▲▲【*復元*】大カテゴリ名変更 ---

// --- ▼▼▼【*復元*】中カテゴリ名変更 (PUT /api/cat2) ---
app.put('/api/cat2/:cat1/:oldName', isAuthenticated, async (req, res) => {
    const { cat1, oldName } = req.params;
    const { newName } = req.body;
    if (!newName) return res.status(400).json({ message: '新しい名前が必要です' });
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        const whereCat1 = (cat1 === defaultCat1) ? `(category_1 = $1 OR category_1 IS NULL)` : `category_1 = $1`;
        const whereCat2 = (oldName === defaultCat2) ? `(category_2 = $2 OR category_2 IS NULL)` : `category_2 = $2`;

        await client.query(
            `UPDATE images SET category_2 = $3 WHERE ${whereCat1} AND ${whereCat2}`,
            [cat1, oldName, newName]
        );
        await client.query(
            `UPDATE folders SET category_2 = $3 WHERE ${whereCat1} AND ${whereCat2}`,
            [cat1, oldName, newName]
        );

        await client.query('COMMIT');
        res.json({ message: `中カテゴリ「${oldName}」を「${newName}」に変更しました。` });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error("!!!!! API PUT /api/cat2 FAILED !!!!!", e);
        res.status(500).json({ message: '中カテゴリ名の変更に失敗しました。' });
    } finally {
        client.release();
    }
});
// --- ▲▲▲【*復元*】中カテゴリ名変更 ---

// --- ▼▼▼【*復元*】小カテゴリ名変更 (PUT /api/cat3) ---
app.put('/api/cat3/:cat1/:cat2/:oldName', isAuthenticated, async (req, res) => {
    const { cat1, cat2, oldName } = req.params;
    const { newName } = req.body;
    if (!newName) return res.status(400).json({ message: '新しい名前が必要です' });

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        const whereCat1 = (cat1 === defaultCat1) ? `(category_1 = $1 OR category_1 IS NULL)` : `category_1 = $1`;
        const whereCat2 = (cat2 === defaultCat2) ? `(category_2 = $2 OR category_2 IS NULL)` : `category_2 = $2`;
        const whereCat3 = (oldName === defaultCat3) ? `(category_3 = $3 OR category_3 IS NULL)` : `category_3 = $3`;

        await client.query(
            `UPDATE images SET category_3 = $4 WHERE ${whereCat1} AND ${whereCat2} AND ${whereCat3}`,
            [cat1, cat2, oldName, newName]
        );
        await client.query(
            `UPDATE folders SET category_3 = $4 WHERE ${whereCat1} AND ${whereCat2} AND ${whereCat3}`,
            [cat1, cat2, oldName, newName]
        );

        await client.query('COMMIT');
        res.json({ message: `小カテゴリ「${oldName}」を「${newName}」に変更しました。` });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error("!!!!! API PUT /api/cat3 FAILED !!!!!", e);
        res.status(500).json({ message: '小カテゴリ名の変更に失敗しました。' });
    } finally {
        client.release();
    }
});
// --- ▲▲▲【*復元*】小カテゴリ名変更 ---

// --- ▼▼▼【*復元*】フォルダ名変更 (PUT /api/folder) ---
app.put('/api/folder/:cat1/:cat2/:cat3/:oldName', isAuthenticated, async (req, res) => {
    const { cat1, cat2, cat3, oldName } = req.params;
    const { newName } = req.body;
    if (!newName) return res.status(400).json({ message: '新しい名前が必要です' });

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        const whereCat1 = (cat1 === defaultCat1) ? `(category_1 = $1 OR category_1 IS NULL)` : `category_1 = $1`;
        const whereCat2 = (cat2 === defaultCat2) ? `(category_2 = $2 OR category_2 IS NULL)` : `category_2 = $2`;
        const whereCat3 = (cat3 === defaultCat3) ? `(category_3 = $3 OR category_3 IS NULL)` : `category_3 = $3`;
        const whereFolder = (oldName === defaultFolder) ? `(folder_name = $4 OR folder_name IS NULL)` : `folder_name = $4`;

        // 1. images テーブルの画像ファイル名を変更 (R2上)
        const { rows: images } = await client.query(
            `SELECT title FROM images WHERE ${whereCat1} AND ${whereCat2} AND ${whereCat3} AND ${whereFolder}`,
            [cat1, cat2, cat3, oldName]
        );
        
        // R2上ではファイル名は変更しない（キー (title) は不変）
        
        // 2. images テーブルの folder_name を更新
        await client.query(
            `UPDATE images SET folder_name = $5 WHERE ${whereCat1} AND ${whereCat2} AND ${whereCat3} AND ${whereFolder}`,
            [cat1, cat2, cat3, oldName, newName]
        );
        
        // 3. folders テーブルの folder_name を更新
        await client.query(
            `UPDATE folders SET folder_name = $5 WHERE ${whereCat1} AND ${whereCat2} AND ${whereCat3} AND ${whereFolder}`,
            [cat1, cat2, cat3, oldName, newName]
        );

        await client.query('COMMIT');
        res.json({ message: `フォルダ「${oldName}」を「${newName}」に変更しました。` });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error("!!!!! API PUT /api/folder FAILED !!!!!", e);
        if (e.code === '23505') { // Unique constraint violation
            res.status(409).json({ message: `フォルダ名「${newName}」は既に存在します。` });
        } else {
            res.status(500).json({ message: 'フォルダ名の変更に失敗しました。' });
        }
    } finally {
        client.release();
    }
});
// --- ▲▲▲【*復元*】フォルダ名変更 ---


// --- ▼▼▼【*復元*】performDelete 関数 と 削除API群 ---

// 汎用削除関数
async function performDelete(res, itemDescription, levelData = {}) {
    const { cat1, cat2, cat3, folder } = levelData;
    let whereClause = "";
    let params = [];
    
    if (folder) { // Level 4: フォルダ削除
        whereClause = `(category_1 = $1 OR ($1 = '${defaultCat1}' AND category_1 IS NULL))
                   AND (category_2 = $2 OR ($2 = '${defaultCat2}' AND category_2 IS NULL))
                   AND (category_3 = $3 OR ($3 = '${defaultCat3}' AND category_3 IS NULL))
                   AND (folder_name = $4 OR ($4 = '${defaultFolder}' AND folder_name IS NULL))`;
        params = [cat1, cat2, cat3, folder];
    } else if (cat3) { // Level 3: 小カテゴリ削除
        whereClause = `(category_1 = $1 OR ($1 = '${defaultCat1}' AND category_1 IS NULL))
                   AND (category_2 = $2 OR ($2 = '${defaultCat2}' AND category_2 IS NULL))
                   AND (category_3 = $3 OR ($3 = '${defaultCat3}' AND category_3 IS NULL))`;
        params = [cat1, cat2, cat3];
    } else if (cat2) { // Level 2: 中カテゴリ削除
        whereClause = `(category_1 = $1 OR ($1 = '${defaultCat1}' AND category_1 IS NULL))
                   AND (category_2 = $2 OR ($2 = '${defaultCat2}' AND category_2 IS NULL))`;
        params = [cat1, cat2];
    } else if (cat1) { // Level 1: 大カテゴリ削除
        whereClause = `(category_1 = $1 OR ($1 = '${defaultCat1}' AND category_1 IS NULL))`;
        params = [cat1];
    } else {
        return res.status(400).json({ message: '削除対象が不明です。' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. 削除対象の画像ファイルキー(title)を DB から取得
        const { rows: images } = await client.query(
            `SELECT title FROM images WHERE ${whereClause}`,
            params
        );

        // 2. R2 から画像ファイルを一括削除
        if (images.length > 0) {
            const keysToDelete = images.map(img => ({ Key: img.title }));
            const deleteCommand = new DeleteObjectsCommand({
                Bucket: R2_BUCKET_NAME,
                Delete: { Objects: keysToDelete }
            });
            await s3Client.send(deleteCommand);
        }
        
        // 3. DB (images) からレコードを削除
        await client.query(
            `DELETE FROM images WHERE ${whereClause}`,
            params
        );
        
        // 4. DB (folders) からレコードを削除
        // フォルダ削除 (Level 4) の場合は、folders テーブルからも削除
        if (folder) {
            await client.query(
                `DELETE FROM folders 
                 WHERE (category_1 = $1 OR ($1 = '${defaultCat1}' AND category_1 IS NULL))
                   AND (category_2 = $2 OR ($2 = '${defaultCat2}' AND category_2 IS NULL))
                   AND (category_3 = $3 OR ($3 = '${defaultCat3}' AND category_3 IS NULL))
                   AND (folder_name = $4 OR ($4 = '${defaultFolder}' AND folder_name IS NULL))`,
                [cat1, cat2, cat3, folder]
            );
        } else {
            // カテゴリ削除 (Level 1-3) の場合は、該当する folders も削除
             await client.query(
                `DELETE FROM folders WHERE ${whereClause}`,
                params
            );
        }

        await client.query('COMMIT');
        res.json({ message: `「${itemDescription}」および関連するすべての画像 (${images.length}件) を削除しました。` });

    } catch (e) {
        await client.query('ROLLBACK');
        console.error(`!!!!! API DELETE FAILED (${itemDescription}) !!!!!`, e);
        res.status(500).json({ message: `「${itemDescription}」の削除に失敗しました。` });
    } finally {
        client.release();
    }
}

app.delete('/api/cat1/:name', isAuthenticated, async (req, res) => {
    await performDelete(res, req.params.name, { cat1: req.params.name });
});

app.delete('/api/cat2/:cat1/:name', isAuthenticated, async (req, res) => {
    await performDelete(res, req.params.name, { cat1: req.params.cat1, cat2: req.params.name });
});

app.delete('/api/cat3/:cat1/:cat2/:name', isAuthenticated, async (req, res) => {
    await performDelete(res, req.params.name, { cat1: req.params.cat1, cat2: req.params.cat2, cat3: req.params.name });
});

app.delete('/api/folder/:cat1/:cat2/:cat3/:name', isAuthenticated, async (req, res) => {
    await performDelete(res, req.params.name, { cat1: req.params.cat1, cat2: req.params.cat2, cat3: req.params.cat3, folder: req.params.name });
});
// --- ▲▲▲【*復元*】performDelete 関数 と 削除API群 ---


// --- ▼▼▼【*復元*】画像移動API ---
app.put('/api/image/:imageTitle', isAuthenticated, async (req, res) => {
    const { imageTitle } = req.params;
    const { category1, category2, category3, folderName } = req.body;
    
    if (!category1 || !category2 || !category3 || !folderName) {
        return res.status(400).json({ message: 'すべてのカテゴリとフォルダ名が必要です' });
    }
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // 1. images テーブルを更新
        const { rowCount } = await client.query(
            `UPDATE images 
             SET category_1 = $1, category_2 = $2, category_3 = $3, folder_name = $4 
             WHERE title = $5`,
            [category1, category2, category3, folderName, imageTitle]
        );
        
        if (rowCount === 0) {
            return res.status(404).json({ message: '対象の画像が見つかりません。' });
        }
        
        // 2. 新しい移動先のフォルダが folders テーブルに存在するか確認、なければ挿入
        await client.query(
            `INSERT INTO folders (category_1, category_2, category_3, folder_name)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (category_1, category_2, category_3, folder_name) DO NOTHING`,
            [category1, category2, category3, folderName]
        );
        
        // 3. (オプション) もし元のフォルダに画像が0件になったら、元のフォルダを folders テーブルから削除することもできる
        // (今回は実装省略。/api/folders の同期ロジックでカバー)

        await client.query('COMMIT');
        res.json({ message: `「${imageTitle}」を「${folderName}」に移動しました。` });
        
    } catch (e) {
        await client.query('ROLLBACK');
        console.error("!!!!! API PUT /api/image FAILED !!!!!", e);
        res.status(500).json({ message: '画像の移動に失敗しました。' });
    } finally {
        client.release();
    }
});
// --- ▲▲▲【*復元*】画像移動API ---


// --- ▼▼▼【*復元*】解析API (Tesseract.js 版) ---
app.post('/api/analyze/:folderName', isAuthenticated, async (req, res) => {
    const { folderName } = req.params;
    let worker;
    try {
        // 1. フォルダ内の画像URLを取得
        const query = (folderName === defaultFolder)
            ? `SELECT title, url FROM images WHERE (folder_name = $1 OR folder_name IS NULL) ORDER BY title`
            : `SELECT title, url FROM images WHERE folder_name = $1 ORDER BY title`;
        const { rows } = await pool.query(query, [folderName]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'フォルダに画像がありません。' });
        }

        // Tesseract ワーカー初期化
        worker = await createWorker('jpn'); // 日本語モデルを使用

        let csv = 'ファイル名,画像URL,解析結果(テキスト)\n';

        for (const image of rows) {
            try {
                // 2. 画像URLから画像データを取得して解析
                // Tesseract.js v4+ は URL を直接処理できる
                const { data: { text } } = await worker.recognize(image.url);
                
                // CSV用に整形 (改行を削除, " を "" にエスケープ)
                const processedText = (text || "").replace(/"/g, '""').replace(/\r?\n|\r/g, ' ');
                
                csv += `"${image.title.replace(/"/g, '""')}",`;
                csv += `"${image.url.replace(/"/g, '""')}",`;
                csv += `"${processedText}"\n`;
            
            } catch (imgError) {
                console.error(`Tesseract OCR Error for ${image.url}:`, imgError);
                csv += `"${image.title.replace(/"/g, '""')}",`;
                csv += `"${image.url.replace(/"/g, '""')}",`;
                csv += `"解析エラー"\n`;
            }
        }
        
        // 3. ワーカーを終了
        await worker.terminate();
        
        // 4. CSVとしてレスポンス
        const safeFolderName = folderName.replace(/[^a-z0-9]/gi, '_').toLowerCase();
        const fileName = `analysis_${safeFolderName}_${new Date().toISOString().split('T')[0]}.csv`;

        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`);
        // UTF-8 BOM
        res.send(Buffer.concat([Buffer.from('\uFEFF', 'utf8'), Buffer.from(csv, 'utf8')]));

    } catch (e) {
        if (worker) await worker.terminate(); // エラー時もワーカーを終了
        console.error("!!!!! API /api/analyze FAILED !!!!!", e);
        res.status(500).json({ message: `解析中にエラーが発生しました: ${e.message}` });
    }
});
// --- ▲▲▲【*復元*】解析API ---


// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable();
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});