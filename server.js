// --- 基本部品の読み込み ---
require('dotenv').config();
const express = require('express');
const path = require('path');
const multer = require('multer');
const { S3Client, PutObjectCommand, DeleteObjectsCommand, CopyObjectCommand, DeleteObjectCommand: S3DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { Pool } = require('pg');

// --- ▼ 認証関連のライブラリ ▼ ---
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs'); 
const PgStore = require('connect-pg-simple')(session); // 修正済（スペース追加）
// --- ▲ 認証関連のライブラリ ▲ ---

const { createWorker } = require('tesseract.js');
const sharp = require('sharp');
const https = require('https');

const app = express();
const port = process.env.PORT || 3000;

// --- 1. データベース (PostgreSQL) 接続 ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// --- Middleware 設定 ---
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// --- ▼ 認証機能 (Session と Passport の設定) ▼ ---

app.use(session({
    store: new PgStore({
        pool: pool,
        tableName: 'user_sessions',
        createTableIfMissing: true 
    }),
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
            if (rows.length === 0) {
                return done(null, false, { message: 'ユーザー名またはパスワードが違います。' });
            }
            const user = rows[0];
            const isMatch = await bcrypt.compare(password, user.password_hash);
            if (isMatch) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'ユーザー名またはパスワードが違います。' });
            }
        } catch (error) {
            return done(error);
        }
    }
));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

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

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.status(401).json({ message: 'ログインが必要です。' });
}

// --- DBテーブル自動作成関数 ---
const createTable = async () => {
    const createImagesTable = `
    CREATE TABLE IF NOT EXISTS images (
      id SERIAL PRIMARY KEY, title VARCHAR(1024) NOT NULL, url VARCHAR(1024) NOT NULL,
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

    const createSessionTable = `
    CREATE TABLE IF NOT EXISTS "user_sessions" (
      "sid" varchar NOT NULL COLLATE "default" PRIMARY KEY,
      "sess" json NOT NULL,
      "expire" timestamp(6) NOT NULL
    ) WITH (OIDS=FALSE);
    CREATE INDEX IF NOT EXISTS "IDX_user_sessions_expire" ON "user_sessions" ("expire");
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
        `CREATE INDEX IF NOT EXISTS idx_images_final_number_sort ON images (CAST( (regexp_matches(regexp_replace(title, '\\.[^.]*$', ''), '([0-9]+)$'))[1] AS INTEGER ) NULLS FIRST, title ASC);`,
        `CREATE INDEX IF NOT EXISTS idx_images_title_length_sort ON images (length(title), title);`
    ];

    try {
        await pool.query(createImagesTable);
        await pool.query(createUsersTable);
        
        // ★重要修正: 壊れている可能性のあるセッションテーブルを一度削除して作り直す
        // (これにより Primary Key エラーなどが解消されます)
        await pool.query('DROP TABLE IF EXISTS "user_sessions" CASCADE;');
        await pool.query(createSessionTable);
        
        for (const query of alterColumns) { await pool.query(query); }
        
        await pool.query('DROP INDEX IF EXISTS idx_images_title_length_and_title;');
        await pool.query('DROP INDEX IF EXISTS idx_images_natural_sort;');
        await pool.query('DROP INDEX IF EXISTS idx_images_water_sort;');
        await pool.query('DROP INDEX IF EXISTS idx_images_final_number_sort;');
        
        for (const query of createIndexes) { await pool.query(query); }
        console.log('Database initialized successfully.');
    } catch (err) { console.error('DB init error:', err); }
};

// --- ストレージ接続 ---
const r2Endpoint = `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
const r2PublicUrl = process.env.R2_PUBLIC_URL;
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME;
const s3Client = new S3Client({
    region: 'auto', endpoint: r2Endpoint,
    credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY },
});

// --- Multer ---
const upload = multer({
    storage: multer.memoryStorage(),
    fileFilter: (req, file, cb) => { 
        if (file.mimetype.startsWith('image/')) { cb(null, true); } else { cb(new Error('画像のみ'), false); } 
    }
});

// -----------------------------------------------------------------
// ★ ルート設定
// -----------------------------------------------------------------

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || password.length < 8) {
        return res.status(400).json({ message: 'ユーザー名と8文字以上のパスワードが必要です。' });
    }
    try {
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [username, passwordHash]);
        res.status(201).json({ message: '登録が成功しました。' });
    } catch (error) {
        if (error.code === '23505') {
            res.status(409).json({ message: 'そのユーザー名はすでに使用されています。' });
        } else {
            console.error('Register Error:', error);
            res.status(500).json({ message: 'サーバーエラーが発生しました。' });
        }
    }
});

// [POST] ログイン
app.post('/api/auth/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) { return next(err); }
        if (!user) {
            return res.status(401).json({ message: info.message || 'ログイン失敗' });
        }
        req.logIn(user, (err) => {
            if (err) { return next(err); } // ここでエラーが起きると 500エラー(HTML) が返り、クライアントで「エラーが発生しました」となる
            return res.json({ message: 'ログイン成功', user: user.username });
        });
    })(req, res, next);
});

app.post('/api/auth/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        req.session.destroy((err) => {
            if (err) { return res.status(500).json({ message: 'ログアウト失敗' }); }
            res.clearCookie('connect.sid');
            res.json({ message: 'ログアウトしました。' });
        });
    });
});

app.get('/api/auth/check', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ loggedIn: true, username: req.user.username });
    } else {
        res.json({ loggedIn: false });
    }
});

// --- 画像関連API (ログイン必須) ---
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => {
    const { category1, category2, category3, folderName } = req.body;
    if (!req.files || req.files.length === 0) return res.status(400).json({ message: 'ファイル未選択' });
    const cat1 = category1.trim(); const cat2 = category2.trim(); const cat3 = category3.trim(); const fName = folderName.trim();
    try {
        const values = []; const params = []; let pIdx = 1;
        for (const file of req.files) {
            const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
            const targetFilename = `${cat1}/${cat2}/${cat3}/${fName}/${originalName}`;
            await s3Client.send(new PutObjectCommand({ Bucket: R2_BUCKET_NAME, Key: targetFilename, Body: file.buffer, ContentType: file.mimetype }));
            const targetUrl = `${r2PublicUrl}/${encodeURIComponent(targetFilename)}`;
            values.push(`($${pIdx++}, $${pIdx++}, $${pIdx++}, $${pIdx++}, $${pIdx++}, $${pIdx++})`);
            params.push(targetFilename, targetUrl, cat1, cat2, cat3, fName);
        }
        await pool.query(`INSERT INTO images (title, url, category_1, category_2, category_3, folder_name) VALUES ${values.join(', ')}`, params);
        res.json({ message: `${req.files.length}件 保存完了` });
    } catch (e) { console.error('Upload Error:', e); res.status(500).json({ message: 'アップロード失敗' }); }
});

app.get('/download-csv', isAuthenticated, async (req, res) => {
    try {
        const { folder, cat1, cat2, cat3 } = req.query;
        let queryText, queryParams;
        const orderBy = "ORDER BY CAST((regexp_matches(regexp_replace(title, '\\.[^.]*$', ''), '([0-9]+)$'))[1] AS INTEGER) NULLS FIRST, title ASC";
        if (folder && cat1 && cat2 && cat3) {
            queryText = `SELECT * FROM images WHERE category_1=$1 AND category_2=$2 AND category_3=$3 AND folder_name=$4 ${orderBy}`; queryParams = [cat1, cat2, cat3, folder];
        } else if (folder) {
            queryText = `SELECT * FROM images WHERE folder_name=$1 ${orderBy}`; queryParams = [folder];
        } else {
            queryText = `SELECT * FROM images ORDER BY category_1, category_2, category_3, folder_name`; queryParams = [];
        }
        const { rows } = await pool.query(queryText, queryParams);
        if (rows.length === 0) return res.status(404).send('データなし');
        let csv = "大カテゴリ,中カテゴリ,小カテゴリ,フォルダ名,題名,URL\n";
        rows.forEach(item => {
            const dot = item.title.lastIndexOf('.'); const titleNoExt = dot > 0 ? item.title.substring(0, dot) : item.title;
            const cols = [item.category_1, item.category_2, item.category_3, item.folder_name, titleNoExt, item.url];
            csv += cols.map(c => `"${(c||'').replace(/"/g,'""')}"`).join(',') + "\n";
        });
        const fName = folder ? `list_${folder}.csv` : 'list_all.csv';
        res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fName)}`); res.status(200).send('\uFEFF' + csv);
    } catch (e) { console.error(e); res.status(500).send('エラー'); }
});

app.get('/api/cat1', isAuthenticated, async (req, res) => { const { rows } = await pool.query('SELECT DISTINCT category_1 FROM images ORDER BY category_1'); res.json(rows.map(r => r.category_1)); });
app.get('/api/cat2/:cat1', isAuthenticated, async (req, res) => { const { rows } = await pool.query('SELECT DISTINCT category_2 FROM images WHERE category_1=$1 ORDER BY category_2', [req.params.cat1]); res.json(rows.map(r => r.category_2)); });
app.get('/api/cat3/:cat1/:cat2', isAuthenticated, async (req, res) => { const { rows } = await pool.query('SELECT DISTINCT category_3 FROM images WHERE category_1=$1 AND category_2=$2 ORDER BY category_3', [req.params.cat1, req.params.cat2]); res.json(rows.map(r => r.category_3)); });
app.get('/api/folders/:cat1/:cat2/:cat3', isAuthenticated, async (req, res) => { const { rows } = await pool.query('SELECT DISTINCT folder_name FROM images WHERE category_1=$1 AND category_2=$2 AND category_3=$3 ORDER BY folder_name', [req.params.cat1, req.params.cat2, req.params.cat3]); res.json(rows.map(r => r.folder_name)); });
app.get('/api/search', isAuthenticated, async (req, res) => {
    const { cat1, cat2, cat3, folder, q, sort, order } = req.query;
    if (!cat1 || !cat2 || !cat3 || !folder) return res.status(400).json({message: 'カテゴリ指定必須'});
    const sortBy = sort === 'title' ? 'title' : 'created_at'; const sortDir = order === 'ASC' ? 'ASC' : 'DESC';
    let sql = `SELECT * FROM images WHERE category_1=$1 AND category_2=$2 AND category_3=$3 AND folder_name=$4`; let params = [cat1, cat2, cat3, folder];
    if (q) { sql += ` AND title ILIKE $5`; params.push(`%${q}%`); }
    sql += ` ORDER BY ${sortBy} ${sortDir}, id ${sortDir}`;
    try { const { rows } = await pool.query(sql, params); res.json(rows); } catch(e) { console.error(e); res.status(500).json({message: '取得失敗'}); }
});

async function performDelete(res, where, params, label) {
    try {
        const { rows } = await pool.query(`SELECT title FROM images WHERE ${where}`, params);
        if (rows.length > 0) {
            const keys = rows.map(r => ({ Key: r.title }));
            for(let i=0; i<keys.length; i+=1000) { await s3Client.send(new DeleteObjectsCommand({ Bucket: R2_BUCKET_NAME, Delete: { Objects: keys.slice(i, i+1000) } })); }
        }
        await pool.query(`DELETE FROM images WHERE ${where}`, params); res.json({ message: `${label} 削除完了` });
    } catch(e) { console.error(e); res.status(500).json({message: '削除失敗'}); }
}
app.put('/api/cat1/:old', isAuthenticated, async(req, res) => { await pool.query('UPDATE images SET category_1=$1 WHERE category_1=$2', [req.body.newName, req.params.old]); res.json({message: '変更完了'}); });
app.delete('/api/cat1/:name', isAuthenticated, async(req, res) => performDelete(res, 'category_1=$1', [req.params.name], '大カテゴリ'));
app.delete('/api/cat2/:c1/:name', isAuthenticated, async(req, res) => performDelete(res, 'category_1=$1 AND category_2=$2', [req.params.c1, req.params.name], '中カテゴリ'));
app.delete('/api/cat3/:c1/:c2/:name', isAuthenticated, async(req, res) => performDelete(res, 'category_1=$1 AND category_2=$2 AND category_3=$3', [req.params.c1, req.params.c2, req.params.name], '小カテゴリ'));
app.delete('/api/folder/:name', isAuthenticated, async(req, res) => performDelete(res, 'folder_name=$1', [req.params.name], 'フォルダ'));

app.post('/api/analyze/:folder', isAuthenticated, async (req, res) => {
    const { folder } = req.params; let worker;
    try {
        const { rows } = await pool.query('SELECT * FROM images WHERE folder_name=$1 ORDER BY title', [folder]);
        if(rows.length===0) return res.status(404).json({message:'画像なし'});
        worker = await createWorker('jpn+eng');
        let results = [];
        for(const img of rows) { results.push({filename: img.title, text: 'OCR Result Placeholder'}); }
        await worker.terminate(); res.status(200).send('CSV Content');
    } catch(e) { if(worker) await worker.terminate(); console.error(e); res.status(500).json({message:'解析失敗'}); }
});

app.listen(port, async () => {
    await createTable();
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});