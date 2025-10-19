// --- 基本部品の読み込み ---
require('dotenv').config();
const express = require('express');
const path = require('path');
const multer = require('multer');
const multerS3 = require('multer-s3');
const { S3Client, DeleteObjectsCommand } = require('@aws-sdk/client-s3');
const { Pool } = require('pg');

// --- 認証（ログイン）用の部品 ---
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
    ssl: {
        rejectUnauthorized: false
    }
});

// --- テンプレートエンジン(EJS) を使う設定 ---
app.engine('html', ejs.renderFile);
app.set('view engine', 'html');
app.set('views', __dirname); 

// --- フォーム送信を読めるようにする設定 ---
app.use(express.json()); 
app.use(express.urlencoded({ extended: false })); 

// --- セッション管理（ログイン状態の維持）設定 ---
app.use(session({
    store: new PgSession({ 
        pool: pool,                
        tableName: 'user_sessions' 
    }),
    secret: process.env.SESSION_SECRET || 'a_very_secret_key_that_should_be_in_env', 
    resave: false,
    saveUninitialized: false, 
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } 
}));
app.use(flash()); 

// --- Passport（認証）の初期設定 ---
app.use(passport.initialize());
app.use(passport.session());

// Passport: ユーザー名を元にDBからユーザー情報を探すロジック
passport.use(new LocalStrategy(
    async (username, password, done) => {
        try {
            const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
            if (rows.length === 0) {
                return done(null, false, { message: 'ユーザー名が見つかりません。' });
            }
            const user = rows[0];
            const isMatch = await bcrypt.compare(password, user.password_hash);
            if (isMatch) {
                return done(null, user); 
            } else {
                return done(null, false, { message: 'パスワードが間違っています。' });
            }
        } catch (err) {
            return done(err);
        }
    }
));

// Passport: ユーザー情報をセッションに保存
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Passport: セッションからユーザー情報を復元
passport.deserializeUser(async (id, done) => {
    try {
        const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        done(null, rows[0]);
    } catch (err) {
        done(err);
    }
});

// --- DBテーブル自動作成関数 (users, sessions, images) ---
const createTable = async () => {
    const userQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash VARCHAR(100) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`;
    const sessionQuery = `
    CREATE TABLE IF NOT EXISTS "user_sessions" (
      "sid" varchar NOT NULL COLLATE "default", "sess" json NOT NULL, "expire" timestamp(6) NOT NULL
    ) WITH (OIDS=FALSE);
    DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'user_sessions_pkey') THEN
        ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE;
    END IF; END $$;
    CREATE INDEX IF NOT EXISTS "IDX_user_sessions_expire" ON "user_sessions" ("expire");
    `;
    const createQuery = `
    CREATE TABLE IF NOT EXISTS images (
      id SERIAL PRIMARY KEY, title VARCHAR(255) NOT NULL, url VARCHAR(1024) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      folder_name VARCHAR(100) DEFAULT 'default_folder',
      category_name VARCHAR(100) DEFAULT 'default_category'
    );`;
    const alterFolderQuery = `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='images' AND column_name='folder_name') THEN ALTER TABLE images ADD COLUMN folder_name VARCHAR(100) DEFAULT 'default_folder'; END IF; END; $$;`;
    const alterCategoryQuery = `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='images' AND column_name='category_name') THEN ALTER TABLE images ADD COLUMN category_name VARCHAR(100) DEFAULT 'default_category'; END IF; END; $$;`;
    
    try {
        await pool.query(userQuery);
        await pool.query(sessionQuery);
        await pool.query(createQuery);
        await pool.query(alterFolderQuery);
        await pool.query(alterCategoryQuery);
        console.log('Database tables (users, sessions, images) are ready.');
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

// --- Multer (アップロード処理) ---
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


// -----------------------------------------------------------------
// ★★★★★ ルート（URL）設定 ★★★★★
// -----------------------------------------------------------------

// --- 認証（ログイン）不要のルート ---

app.get('/login', (req, res) => {
    res.render('login.html', { messages: req.flash('error') });
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/', 
    failureRedirect: '/login', 
    failureFlash: true 
}));

app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        res.redirect('/login'); 
    });
});


// --- ★★★ ここから下は、すべて「ログイン必須」のルート ★★★ ---

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) { 
        return next(); 
    }
    res.redirect('/login');
}

app.get('/', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => {
    const { categoryName, folderName } = req.body; 
    if (!categoryName || categoryName.trim() === '') { return res.status(400).json({ message: 'カテゴリ名が指定されていません。' }); }
    if (!folderName || folderName.trim() === '') { return res.status(400).json({ message: 'フォルダ名が指定されていません。' }); }
    if (req.files && req.files.length > 0) {
        try {
            const insertPromises = req.files.map(file => {
                const fileUrl = `${r2PublicUrl}/${encodeURIComponent(file.key)}`;
                const title = file.key;
                return pool.query(
                    'INSERT INTO images (title, url, folder_name, category_name) VALUES ($1, $2, $3, $4)',
                    [title, fileUrl, folderName, categoryName]
                );
            });
            await Promise.all(insertPromises);
            res.json({ message: `「${categoryName} / ${folderName}」に ${req.files.length} 件の画像をアップロードしました。` });
        } catch (dbError) {
            console.error('Database insert error:', dbError);
            res.status(500).json({ message: 'データベースへの保存に失敗しました。' });
        }
    } else {
        res.status(400).json({ message: 'アップロードするファイルが選択されていません。' });
    }
});

app.get('/download-csv', isAuthenticated, async (req, res) => {
    try {
        const { folder } = req.query; 
        let queryText; let queryParams;
        if (folder) {
            queryText = 'SELECT title, url, folder_name, category_name FROM images WHERE folder_name = $1 ORDER BY created_at DESC';
            queryParams = [folder];
        } else {
            queryText = 'SELECT title, url, folder_name, category_name FROM images ORDER BY category_name, folder_name, created_at DESC';
            queryParams = [];
        }
        const { rows } = await pool.query(queryText, queryParams);
        if (rows.length === 0) { res.status(404).send('対象の履歴がありません。'); return; }
        let csvContent = "カテゴリ名,フォルダ名,題名,URL\n";
        rows.forEach(item => {
            const category = `"${(item.category_name || 'default').replace(/"/g, '""')}"`;
            const f = `"${(item.folder_name || 'default').replace(/"/g, '""')}"`;
            const title = `"${item.title.replace(/"/g, '""')}"`;
            const url = `"${item.url.replace(/"/g, '""')}"`;
            csvContent += `${category},${f},${title},${url}\n`;
        });
        const fileName = folder ? `upload_list_${folder}.csv` : 'upload_list_all.csv';
        const bom = '\uFEFF';
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        res.status(200).send(bom + csvContent);
    } catch (dbError) {
        console.error('Database select error:', dbError);
        res.status(500).send('データベースからの読み込みに失敗しました。');
    }
});

app.get('/api/categories', isAuthenticated, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT DISTINCT category_name FROM images ORDER BY category_name');
        res.json(rows.map(row => row.category_name)); 
    } catch (dbError) {
        console.error('API /api/categories error:', dbError);
        res.status(500).json({ message: 'カテゴリの読み込みに失敗しました。' });
    }
});

app.get('/api/folders_by_category/:categoryName', isAuthenticated, async (req, res) => {
    try {
        const { categoryName } = req.params; 
        const { rows } = await pool.query(
            'SELECT DISTINCT folder_name FROM images WHERE category_name = $1 ORDER BY folder_name', [categoryName]
        );
        res.json(rows.map(row => row.folder_name));
    } catch (dbError) {
        console.error('API /api/folders_by_category error:', dbError);
        res.status(500).json({ message: 'フォルダの読み込みに失敗しました。' });
    }
});

app.get('/api/images_by_folder/:folderName', isAuthenticated, async (req, res) => {
    try {
        const { folderName } = req.params; 
        const { rows } = await pool.query(
            'SELECT title, url FROM images WHERE folder_name = $1 ORDER BY created_at DESC', [folderName]
        ); 
        res.json(rows); 
    } catch (dbError) {
        console.error('API /api/images_by_folder error:', dbError);
        res.status(500).json({ message: '画像の読み込みに失敗しました。' });
    }
});

app.delete('/api/folder/:folderName', isAuthenticated, async (req, res) => {
    const { folderName } = req.params;
    try {
        const { rows } = await pool.query('SELECT title FROM images WHERE folder_name = $1', [folderName]);
        if (rows.length > 0) {
            const objectsToDelete = rows.map(row => ({ Key: row.title }));
            const deleteCommand = new DeleteObjectsCommand({
                Bucket: R2_BUCKET_NAME,
                Delete: { Objects: objectsToDelete },
            });
            await s3Client.send(deleteCommand);
        }
        await pool.query('DELETE FROM images WHERE folder_name = $1', [folderName]);
        res.json({ message: `フォルダ「${folderName}」を完全に削除しました。` });
    } catch (error) {
        console.error(`Failed to delete folder ${folderName}:`, error);
        res.status(500).json({ message: 'フォルダの削除に失敗しました。サーバーエラーが発生しました。' });
    }
});


// ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼
// 
// 11. 【★セットアップ用コード★】 は削除済みです。
// 
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable(); 
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});