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
    secret: process.env.SESSION_SECRET || 'default_session_secret_change_this', // Ensure this is strong and in .env
    resave: false, saveUninitialized: false,
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
        } catch (err) { return done(err); }
    }
));
passport.serializeUser((user, done) => { done(null, user.id); });
passport.deserializeUser(async (id, done) => {
    try {
        const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        done(null, rows[0]);
    } catch (err) { done(err); }
});

// --- DBテーブル自動作成関数 (★4階層対応) ---
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
    const alterCat1Query = `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_1') THEN ALTER TABLE images ADD COLUMN category_1 VARCHAR(100) DEFAULT 'default_cat1'; END IF; END $$;`;
    const alterCat2Query = `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_2') THEN ALTER TABLE images ADD COLUMN category_2 VARCHAR(100) DEFAULT 'default_cat2'; END IF; END $$;`;
    const alterCat3Query = `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_3') THEN ALTER TABLE images ADD COLUMN category_3 VARCHAR(100) DEFAULT 'default_cat3'; END IF; END $$;`;
    const alterFolderQuery = `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='folder_name') THEN ALTER TABLE images ADD COLUMN folder_name VARCHAR(100) DEFAULT 'default_folder'; END IF; END $$;`;

    try {
        await pool.query(userQuery);
        await pool.query(sessionQuery);
        await pool.query(createQuery);
        await pool.query(alterCat1Query);
        await pool.query(alterCat2Query);
        await pool.query(alterCat3Query);
        await pool.query(alterFolderQuery);
        console.log('Database tables (users, sessions, images with 4 levels) are ready.');
    } catch (err) {
        console.error('Failed to create/update database tables:', err);
    }
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
        else { cb(new Error('画像ファイルのみアップロード可能です。'), false); }
    }
});

// --- ログインチェック関数 ---
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) { return next(); }
    res.redirect('/login');
}

// -----------------------------------------------------------------
// ★★★★★ ルート（URL）設定 ★★★★★
// -----------------------------------------------------------------

// --- 認証不要ルート (ログイン/ログアウト) ---
app.get('/login', (req, res) => { res.render('login.html', { messages: req.flash('error') }); });
app.post('/login', passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login', failureFlash: true }));
app.get('/logout', (req, res, next) => { req.logout((err) => { if (err) { return next(err); } res.redirect('/login'); }); });

// --- ログイン必須ルート ---

app.get('/', isAuthenticated, (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

// ▼▼▼ アップロードAPI (/upload) (★4階層対応) ▼▼▼
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => {
    const { category1, category2, category3, folderName } = req.body;
    if (!category1 || !category2 || !category3 || !folderName ) {
        return res.status(400).json({ message: 'すべてのカテゴリとフォルダ名を入力してください。' });
    }
    if (req.files && req.files.length > 0) {
        try {
            const insertPromises = req.files.map(file => {
                const fileUrl = `${r2PublicUrl}/${encodeURIComponent(file.key)}`;
                const title = file.key;
                return pool.query(
                    `INSERT INTO images (title, url, category_1, category_2, category_3, folder_name)
                     VALUES ($1, $2, $3, $4, $5, $6)`,
                    [title, fileUrl, category1.trim(), category2.trim(), category3.trim(), folderName.trim()] // Trim inputs
                );
            });
            await Promise.all(insertPromises);
            res.json({ message: `「${category1}/${category2}/${category3}/${folderName}」に ${req.files.length} 件保存しました。` });
        } catch (dbError) {
            console.error('Database insert error:', dbError);
            res.status(500).json({ message: 'データベースへの保存に失敗しました。' });
        }
    } else {
        res.status(400).json({ message: 'アップロードするファイルが選択されていません。' });
    }
});

// フォルダ別CSV API (/download-csv) (★4階層対応に修正)
app.get('/download-csv', isAuthenticated, async (req, res) => {
    try {
        const { folder } = req.query; // Only folder name is used for filtering for now
        let queryText; let queryParams;
        if (folder) {
            queryText = 'SELECT title, url, category_1, category_2, category_3, folder_name FROM images WHERE folder_name = $1 ORDER BY created_at DESC';
            queryParams = [folder];
        } else {
            queryText = 'SELECT title, url, category_1, category_2, category_3, folder_name FROM images ORDER BY category_1, category_2, category_3, folder_name, created_at DESC';
            queryParams = [];
        }
        const { rows } = await pool.query(queryText, queryParams);
        if (rows.length === 0) { return res.status(404).send('対象の履歴がありません。'); }

        let csvContent = "大カテゴリ,中カテゴリ,小カテゴリ,フォルダ名,題名,URL\n";
        rows.forEach(item => {
            const c1 = `"${(item.category_1 || '').replace(/"/g, '""')}"`;
            const c2 = `"${(item.category_2 || '').replace(/"/g, '""')}"`;
            const c3 = `"${(item.category_3 || '').replace(/"/g, '""')}"`;
            const f = `"${(item.folder_name || '').replace(/"/g, '""')}"`;
            const title = `"${item.title.replace(/"/g, '""')}"`;
            const url = `"${item.url.replace(/"/g, '""')}"`;
            csvContent += `${c1},${c2},${c3},${f},${title},${url}\n`;
        });
        const fileName = folder ? `list_${folder}.csv` : 'list_all.csv';
        const bom = '\uFEFF';
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`); // Ensure filename encoding
        res.status(200).send(bom + csvContent);
    } catch (dbError) {
        console.error('CSV download error:', dbError);
        res.status(500).send('CSV生成に失敗しました。');
    }
});

// --- ギャラリー用API (★4階層取得用) ---
app.get('/api/cat1', isAuthenticated, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT DISTINCT category_1 FROM images ORDER BY category_1');
        res.json(rows.map(row => row.category_1));
    } catch (dbError) { console.error('API Error:', dbError); res.status(500).json({ message: 'Error fetching Cat1' }); }
});
app.get('/api/cat2/:cat1', isAuthenticated, async (req, res) => {
    try {
        const { cat1 } = req.params;
        const { rows } = await pool.query( 'SELECT DISTINCT category_2 FROM images WHERE category_1 = $1 ORDER BY category_2', [cat1] );
        res.json(rows.map(row => row.category_2));
    } catch (dbError) { console.error('API Error:', dbError); res.status(500).json({ message: 'Error fetching Cat2' }); }
});
app.get('/api/cat3/:cat1/:cat2', isAuthenticated, async (req, res) => {
    try {
        const { cat1, cat2 } = req.params;
        const { rows } = await pool.query( 'SELECT DISTINCT category_3 FROM images WHERE category_1 = $1 AND category_2 = $2 ORDER BY category_3', [cat1, cat2] );
        res.json(rows.map(row => row.category_3));
    } catch (dbError) { console.error('API Error:', dbError); res.status(500).json({ message: 'Error fetching Cat3' }); }
});
app.get('/api/folders/:cat1/:cat2/:cat3', isAuthenticated, async (req, res) => {
    try {
        const { cat1, cat2, cat3 } = req.params;
        const { rows } = await pool.query( 'SELECT DISTINCT folder_name FROM images WHERE category_1 = $1 AND category_2 = $2 AND category_3 = $3 ORDER BY folder_name', [cat1, cat2, cat3] );
        res.json(rows.map(row => row.folder_name));
    } catch (dbError) { console.error('API Error:', dbError); res.status(500).json({ message: 'Error fetching folders' }); }
});
app.get('/api/images/:folderName', isAuthenticated, async (req, res) => { // Endpoint changed back for simplicity
    try {
        const { folderName } = req.params;
        const { rows } = await pool.query( 'SELECT title, url FROM images WHERE folder_name = $1 ORDER BY created_at DESC', [folderName] );
        res.json(rows);
    } catch (dbError) { console.error('API Error:', dbError); res.status(500).json({ message: 'Error fetching images' }); }
});
app.get('/api/search', isAuthenticated, async (req, res) => {
    const { folder, q } = req.query;
    if (!folder) { return res.status(400).json({ message: 'フォルダ指定必須' }); }
    try {
        let queryText; let queryParams;
        if (q && q.trim() !== '') {
             const searchTerm = `%${q}%`;
             queryText = `SELECT title, url FROM images WHERE folder_name = $1 AND title ILIKE $2 ORDER BY created_at DESC`;
             queryParams = [folder, searchTerm];
        } else {
             queryText = `SELECT title, url FROM images WHERE folder_name = $1 ORDER BY created_at DESC`;
             queryParams = [folder];
        }
        const { rows } = await pool.query(queryText, queryParams);
        res.json(rows);
    } catch (dbError) { console.error('API Error:', dbError); res.status(500).json({ message: '検索失敗' }); }
});

// フォルダ削除API (/api/folder/:folderName)
app.delete('/api/folder/:folderName', isAuthenticated, async (req, res) => {
    const { folderName } = req.params;
    try {
        const { rows } = await pool.query('SELECT title FROM images WHERE folder_name = $1', [folderName]);
        if (rows.length > 0) {
            const objectsToDelete = rows.map(row => ({ Key: row.title }));
            const deleteCommand = new DeleteObjectsCommand({ Bucket: R2_BUCKET_NAME, Delete: { Objects: objectsToDelete } });
            await s3Client.send(deleteCommand);
            console.log(`Deleted ${objectsToDelete.length} objects from R2 for folder: ${folderName}`);
        }
        await pool.query('DELETE FROM images WHERE folder_name = $1', [folderName]);
        res.json({ message: `フォルダ「${folderName}」削除完了` });
    } catch (error) { console.error(`Delete folder error:`, error); res.status(500).json({ message: '削除失敗' }); }
});

// フォルダ名変更API (/api/folder/:oldFolderName)
app.put('/api/folder/:oldFolderName', isAuthenticated, async (req, res) => {
    const { oldFolderName } = req.params;
    const { newFolderName } = req.body;
    // ★ 完全な入力チェックを追加
    if (!newFolderName || newFolderName.trim() === '') {
        return res.status(400).json({ message: '新しいフォルダ名が指定されていません。' });
    }
    if (newFolderName.trim() === oldFolderName) {
         return res.status(400).json({ message: '新しい名前が現在の名前と同じです。' });
    }
    try {
        const updateQuery = `UPDATE images SET folder_name = $1 WHERE folder_name = $2`;
        const result = await pool.query(updateQuery, [newFolderName.trim(), oldFolderName]);
        res.json({ message: `フォルダ名を変更しました。` });
    } catch (error) {
         console.error(`Rename folder error:`, error);
         res.status(500).json({ message: '名前変更失敗' }); // Keep error handling simple for now
    }
});

// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable(); // ★起動時にDBを自動改造
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});